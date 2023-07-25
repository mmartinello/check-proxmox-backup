#!/usr/bin/env python3

"""
Nagios/Icinga plugin to monitor virtual machines backups of a Proxmox VE node

authors:
    Mattia Martinello - mattia@mattiamartinello.com
"""

_VERSION = '1.0'
_VERSION_DESCR = 'Monitors virtual machines backups of a Proxmox VE node.'

import argparse
from datetime import datetime
import logging
from proxmoxer import ProxmoxAPI
import sys
import re
import time

ICINGA_OK = 0
ICINGA_WARNING = 1
ICINGA_CRITICAL = 2
ICINGA_UNKNOWN = 3
ICINGA_LABELS = {0: 'OK', 1: 'WARNING', 2: 'CRITICAL', 3: 'UNKNOWN'}

def icinga_exit(level, details=None, perfdata=[]):
    """Exit to system producing an output conform
    to the Icinga standards.
    """
    # choose the right stream
    stream = sys.stdout if level == ICINGA_OK else sys.stderr

    # build the message as level + details
    msg = ICINGA_LABELS.get(level)
    if details:
        msg = '{} - {}'.format(msg, details)

    # add perfata if given
    if len(perfdata):
        perfdata_string = ' '.join(perfdata)
        msg = '{} |{}'.format(msg, perfdata_string)

    # exit with status and message
    print(msg, file=stream)
    sys.exit(level)

def exit_with_error(message):
    """Exit with the Icinga Unknown status code and the given error
    """

    message = 'ERROR: {}'.format(message)
    icinga_exit(ICINGA_UNKNOWN, message)


class Checker:
    """Parse the command line, run checks and return status.
    """

    def __init__(self):
        # init the cmd line parser
        parser = argparse.ArgumentParser(
            description='Icinga plugin: check_pve_backups'
        )
        self.add_arguments(parser)

        # read the command line
        args = parser.parse_args()

        # manage arguments
        self._manage_arguments(args)

        self._proxmox = None

    def add_arguments(self, parser):
        """Add command arguments to the argument parser.
        """
        
        # username argument validator: user@realm
        def pve_api_username(arg_value, pat=re.compile(r"^.+@[a-z|A-Z]+$")):
            if not pat.match(arg_value):
                raise argparse.ArgumentTypeError(
                    'invalid value: has to be username@realm'
                )
            return arg_value

        parser.add_argument(
            '-V', '--version',
            action='version',
            version = '%(prog)s v{} - {}'.format(_VERSION, _VERSION_DESCR)
        )

        parser.add_argument(
            'check',
            choices=['not_backed_up', 'backups'],
            help='The check to be done:'
                 ' (not_backed_up = virtual machines not backed up)'
                 ' (backups = available backups for virtual machines)'
        )

        parser.add_argument(
            '--debug',
            action="store_true",
            help='Print debugging info to console. This may make the plugin '
                 'not working with Icinga since it prints stuff to console.'
        )

        parser.add_argument(
            '--debug2',
            action="store_true",
            help='Print exceptions to console. This may make the plugin'
                 ' not working and get wrong results with Icinga since it'
                 ' prints stuff to console.'
        )

        parser.add_argument(
            '-H', '--host',
            dest='host',
            default='localhost',
            help='The Proxmox API host'
        )

        parser.add_argument(
            '-P', '--port',
            dest='port',
            type=int,
            default=3306,
            help='The Proxmox port'
        )

        parser.add_argument(
            '-u', '--username',
            dest='username',
            type=pve_api_username,
            required=True,
            help='The Proxmox API username (username@realm)'
        )

        parser.add_argument(
            '-p', '--password',
            dest='password',
            required=True,
            help='The Proxmox API password'
        )

        parser.add_argument(
            '--verify-ssl',
            action='store_true',
            help='Verify the SSL certificate'
        )

        parser.add_argument(
            '-l', '--level',
            choices=['warning', 'critical'],
            dest='level',
            default=None,
            help='The Icinga error level to raise in case of failure'
                 ' (\'not_backed_up\' check only)'
        )

        parser.add_argument(
            '-s', '--storage',
            dest='storage',
            help='The backup storage'
        )

        parser.add_argument(
            '-n', '--node',
            dest='node',
            help='Filter the VMs running on this Proxmox node'
        )

        parser.add_argument(
            '-t', '--timeout',
            dest='timeout',
            default=300,
            type=int,
            help='The timeout in seconds'
        )

        vms_group = parser.add_mutually_exclusive_group()

        vms_group.add_argument(
            '-i', '--include', '--vmid',
            action='append',
            dest='included_vmids',
            type=int,
            default=[],
            help='List of VM IDs to be checked'
        )

        vms_group.add_argument(
            '-e', '--exclude',
            action='append',
            dest='excluded_vmids',
            type=int,
            default=[],
            help='List of VM IDs to be excluded from check'
        )

        parser.add_argument(
            '-w', '--warning',
            dest='warning',
            type=int,
            help='Warning threshold in minutes'
        )

        parser.add_argument(
            '-c', '--critical',
            dest='critical',
            type=int,
            help='Critical threshold in minutes'
        )

    def _manage_arguments(self, args):
        """Get command arguments from the argument parser and load them.
        """

        # positional: check to be done
        self.check = getattr(args, 'check')

        # debug flag
        self.debug = getattr(args, 'debug', False)
        self.debug2 = getattr(args, 'debug2', False)
        if self.debug or self.debug2:
            logging.basicConfig(level=logging.DEBUG)

        # the Proxmox API host
        self.host = getattr(args, 'host', 'localhost')

        # the Proxmox API port
        self.port = getattr(args, 'port', 3306)

        # the Proxmox API username
        self.username = getattr(args, 'username')

        # the Proxmox API password
        self.password = getattr(args, 'password')

        # the Proxmox API password
        self.verify_ssl = getattr(args, 'verify_ssl', False)

        # included VM IDs
        self.included_vmids = getattr(args, 'included_vmids', [])

        # excluded VM IDs
        self.excluded_vmids = getattr(args, 'excluded_vmids', [])

        # backup storage
        self.storage = getattr(args, 'storage')

        # print arguments (debug)
        logging.debug('Command arguments: {}'.format(args))

        # error level (only in 'not_backed_up' check mode, else exit)
        level = getattr(args, 'level', None)
        if level and self.check != 'not_backed_up':
            exit_with_error('level not allowed on this check mode')
        else:
            self.level = getattr(args, 'level', 'critical')

        # storage required in backups check mode
        if self.check == 'backups' and not self.storage:
            exit_with_error('storage required in backups check mode')

        # Proxmox node
        self.node = getattr(args, 'node', None)

        # Timeout
        self.timeout = getattr(args, 'timeout', 300)

        # Warning threshold in minutes
        self.warning = getattr(args, 'warning')
        if self.check != 'backups' and self.warning:
            exit_with_error(
                'Warning threshold not allowed in backups check mode'
            )
        if self.check == 'backups' and not self.warning:
            exit_with_error('Warning threshold required in backups check mode')

        # Critical threshold in minutes
        self.critical = getattr(args, 'critical')
        if self.check != 'backups' and self.critical:
            exit_with_error(
                'Critical threshold not allowed in backups check mode'
            )
        if self.check == 'backups' and not self.critical:
            exit_with_error(
                'Critical threshold required in backups check mode'
            )

    def handle(self):
        """Connect to Proxmox API, start the requested check and give result.
        """

        # connect to Proxmox and ask for VMs not backed up
        # self.proxmox = self._pve_connect()
        
        # not backed up virtual machines check mode
        if self.check == 'not_backed_up':
            self._check_vm_not_backed_up()
        elif self.check == 'backups':
            self._check_vm_backups()
        else:
            exit_with_error('Unsupported check mode: {}'.format(self.check))

    @property
    def proxmox(self):
        if self._proxmox is None:
            self._proxmox = self._pve_connect()
        
        return self._proxmox

    def _get_included_vmids(self):
        """Get included VM IDs
        """

        included_vmids = list(set(self.included_vmids))
        logging.debug("Included VMs: {}".format(included_vmids))
        return included_vmids

    def _get_excluded_vmids(self):
        """Get excluded VM IDs
        """

        excluded_vmids = list(set(self.excluded_vmids))
        logging.debug("Excluded VMs: {}".format(excluded_vmids))
        return excluded_vmids

    def _check_vm_not_backed_up(self):
        """Check if there are virtual machines without backup jobs
        """

        # get included and excluded VMs if requested
        included_vmids = self._get_included_vmids()
        excluded_vmids = self._get_excluded_vmids()

        # get virtual machines on selected node if given
        filtered_vmdids = None
        if self.node:
            filtered_vmdids = self._get_node_vms(self.node)

        not_backed_up_vms = self._get_vms_not_backed_up(
            filtered_vmdids,
            included_vmids,
            excluded_vmids
        )

        # compose perfdata
        not_backed_up_count = len(not_backed_up_vms)
        perfdata = ['not_backed_up={}'.format(not_backed_up_count)]

        # check included not backed up virtual machines
        if not_backed_up_count > 0:
            if not_backed_up_count == 1:
                plural = ''
            else:
                plural = 's'

            # compose the exit message elements
            elements = []
            for vm in not_backed_up_vms:
                if vm['type'] == 'qemu':
                    type = 'VM'
                elif vm['type'] == 'lxc':
                    type = 'CT'

                vmid = vm['vmid']
                name = vm['name']
                element = "{} {} ({})".format(type, vmid, name)
                elements.append(element)

            # compose exit message
            details = ', '.join(elements)
            msg = "{} VM{} not backed up: {}"
            msg = msg.format(not_backed_up_count, plural, details)
            logging.debug(msg)

            # exit with the correct level
            if self.level == 'critical':
                level = ICINGA_CRITICAL
            elif self.level == 'warning':
                level = ICINGA_WARNING

            icinga_exit(level, msg, perfdata)

        else:
            msg = 'All VMs are backed up'
            icinga_exit(ICINGA_OK, msg, perfdata)

    def _get_vms_not_backed_up(self, filtered_vms=None, included_vmids=[],
                               excluded_vmids=[]):
        """Get the filtered list of the not backed up virtual machines

        Args:
            filtered_vms (list): the VM IDS to check (None if all)
            included_vms (list): the VM IDS to include in the response
            excluded_vms (list): the VM IDS to exclude from the response

        Return:
            a list of dictonaries with info about VMs not backed up, in this
            format:

            [
                {
                    'name': 'foo',
                    'vmid': 101,
                    'type': 'qemu'
                },
                {
                    'name': 'bar',
                    'vmid': 102,
                    'type': 'lxc'
                }
            ]
        """

        # get VMs not backed up in the whole cluster
        url = '/cluster/backup-info/not-backed-up'
        cluster_not_backed_up_vms = self.proxmox(url).get()
        
        msg = 'Cluster VMs not backed up in the whole cluster: {}'
        msg = msg.format(cluster_not_backed_up_vms)
        logging.debug(msg)

        # not backed up virtual machines
        self.not_backed_up_vms = []

        # cycle VMs not backed up in the cluster
        for vm in cluster_not_backed_up_vms:
            vmid = vm['vmid']

            if filtered_vms:
                if vmid in filtered_vms:
                    if included_vmids:
                        if vmid in included_vmids:
                            self._add_not_backed_up_vm(vm)
                            continue
                        else:
                            continue
                    if excluded_vmids:
                        if vmid not in excluded_vmids:
                            self._add_not_backed_up_vm(vm)
                            continue
                        else:
                            continue
                    else:
                        self._add_not_backed_up_vm(vm)
                        continue
                else:
                    continue
            else:
                if included_vmids:
                    if vmid in included_vmids:
                        self._add_not_backed_up_vm(vm)
                        continue
                    else:
                        continue
                if excluded_vmids:
                    if vmid not in excluded_vmids:
                        self._add_not_backed_up_vm(vm)
                        continue
                    else:
                        continue

        return self.not_backed_up_vms

    def _add_not_backed_up_vm(self, vm):
        """Add the given virtual machine info to the not backed up virtual
        machines list

        Args:
            vm (dict): a dict containing virtual machine info, for example:
                {
                    'name': 'test-not-backed-up',
                    'vmid': 9999,
                    'type': 'qemu|lxc'
                }
        """

        vmid = vm['vmid']
        msg = 'Adding the VMID {} to not backed up list'
        logging.debug(msg.format(vmid))

        self.not_backed_up_vms.append(vm)

    def _check_vm_backups(self):
        """Check available backups for virtual machines
        """

        # If included VM IDs are given get backups for these VMs
        if self.included_vmids:
            vmids = self.included_vmids
        # Else, if node is given, get vms running on the given node
        elif self.node:
            node_name = self.node
            vmids = self._get_node_vms(node_name)
        # Else, don't filter vms
        else:
            vmids = []

        # If excluded VM IDs are given, exclude them from the VM list
        if self.excluded_vmids:
            for vmid in self.excluded_vmids:
                if vmid in vmids:
                    vmids.remove(vmid)

        # Get backups for given VM ids 
        backups = self._get_backups(self.node, self.storage, vmids)
        logging.debug("Available backups: {}".format(backups))

        # Get thresholds in seconds
        warning_sec = self.warning
        critical_sec = self.critical

        # Comprare backups age with thresholds
        ok_backups = {}
        warning_backups = {}
        critical_backups = {}
        unavailable_backups = []

        # Current timestamp
        current_timestamp = time.time()
        logging.debug("Current timestamp: {}".format(current_timestamp))

        # Iterate VM IDs and compare thresholds
        for vmid in vmids:
            if vmid not in backups:
                logging.debug("No backups for VM {} available".format(vmid))
                unavailable_backups.append(vmid)
            else:
                backup = backups[vmid]
                age_sec = current_timestamp - backup['ctime']

                if age_sec > critical_sec:
                    critical_backups[vmid] = backup
                elif age_sec > warning_sec:
                    warning_backups[vmid] = backup
                else:
                    ok_backups[vmid] = backup

        # Compose the return data
        data = {
            'unavailable': unavailable_backups,
            'critical': critical_backups,
            'warning': warning_backups,
            'ok': ok_backups
        }

        logging.debug(data)

        # Compose exit value and messages
        messages = {}
        perfdata = []
        backup_msg = 'backup for VMID {} is {} old'
        if data['unavailable']:
            vms = [ str(i) for i in data['unavailable'] ]
            logging.debug("VMS: {}".format(vms))
            msg = 'VMS WITH NO BACKUPS: {}'.format(', '.join(vms))
            messages['unavailable'] = msg
        if data['critical']:
            vm_messages = []
            for vmid, backup in data['critical'].items():
                vm_messages.append(backup_msg.format(vmid, backup['ctime']))
            msg = 'CRITICAL BACKUPS: {}'.format(', '.join(vm_messages))
            messages['critical'] = msg
        if data['warning']:
            vm_messages = []
            for vmid, backup in data['warning'].items():
                vm_messages.append(backup_msg.format(vmid, backup['ctime']))
            msg = 'WARNING BACKUPS: {}'.format(', '.join(vm_messages))
            messages['warning'] = msg
        if data['ok']:
            vm_messages = []
            for vmid, backup in data['warning'].items():
                vm_messages.append(backup_msg.format(vmid, backup['ctime']))
            msg = 'OK BACKUPS: {}'.format(', '.join(vm_messages))
            messages['ok'] = msg

        logging.debug("Composed messages: {}".format(messages))
        message = '; '.join(map(str, messages.values()))

        # Decide exit message
        if messages['unavailable'] or messages['critical']:
            exit_code = ICINGA_CRITICAL
        elif messages['warning']:
            exit_code = ICINGA_WARNING
        elif messages['ok']:
            exit_code = ICINGA_OK
        else:
            exit_code = ICINGA_UNKNOWN

        # Exit
        icinga_exit(exit_code, message, perfdata)

    def _get_backups(self, node_name, storage_name, vmids=[]):
        """Get backups stored into the given storage on the given PVE node.
        If a list of VM IDs is provided, only backups of the listed VMs are
        taken.

        Args:
            node_name (string): the name of the PVE cluster node
            storage_name (string): the name of the storage to list backups from
            vmids (list): the list of IDs of virtual machines to get backups
                for
        """

        url = 'nodes/{}/storage/{}/content'
        url = url.format(node_name, storage_name)
        backups = self.proxmox(url).get(content='backup')
        self.backups = {}

        # cycle backup list
        for backup in backups:
            vmid = backup['vmid']
            ctime = backup['ctime']
            backup = {'vmid': vmid, 'ctime': ctime}

            # if vmids not provided, consider all backups
            if not vmids:
                self._add_backup(backup)
                continue
            # else check if the backup vmid is into the vmids list
            if vmids and vmid in vmids:
                self._add_backup(backup)
                continue
                
        return self.backups

    def _add_backup(self, backup):
        """Insert the given backup in the backup list, only if the given
        backup is newer than the already existing backup for the backup vmid

        Args:
            backup (dict): a dict containing backup info, for example:
                {
                    'vmid': 9999,
                    'ctime': 1659225602 (creation timestamp)
                }
        """

        vmid = backup['vmid']
        ctime = backup['ctime']

        # if there are not backups for this vmid, add
        if vmid not in self.backups:
            msg = 'Adding a backup for the VMID {} '
            msg+= 'because I have no backups for this VMID'
            #logging.debug(msg.format(vmid))
            self.backups[vmid] = backup
        else:
            existing_backup = self.backups[vmid]
            if ctime > existing_backup['ctime']:
                msg = 'Adding a backup for the VMID {} '
                msg+= 'because it is the last one'
                #logging.debug(msg.format(vmid))
                self.backups[vmid] = backup
            else:
                return None

        # return the inserted backup
        return backup

    def _pve_connect(self):
        """Connect to Proxmox VE API
        """

        # compose the Proxmox API host (host:port)
        host = '{}:{}'.format(self.host, self.port)

        msg = 'Connecting to Proxmox API at host {} with username {} ...'
        msg = msg.format(host, self.username)
        logging.debug(msg)

        # create a new connection to Proxmox API
        proxmox = ProxmoxAPI(
            host,
            user=self.username,
            password=self.password,
            verify_ssl=self.verify_ssl,
            backend='https',
            service='pve',
            timeout=self.timeout
        )

        return proxmox

    def _get_node_vms(self, node_name):
        """Get the virtual machines running on a specific PVE node

        Args:
            node_name (str): the name of the node to get the VM list for

        Return:
            a list of dictonaries with info about VMs running on the given
            PVE node
        """

        # get info about qemu and lxc virtual machines
        node_vms = []
        url = 'nodes/{}/{}'
        vm_types = ['qemu', 'lxc']
        for vm_type in vm_types:
            vms = self.proxmox(url.format(node_name, vm_type)).get()

            for vm in vms:
                node_vms.append(int(vm['vmid']))

        vm_count = len(node_vms)
        msg = '{} virtual machines on node {}: {}'
        msg = msg.format(vm_count, node_name, node_vms)
        logging.debug(msg)

        return node_vms


if __name__ == "__main__":
    # run the procedure and get results: if I get an exception I exit with
    # the Icinga UNKNOWN status code
    main = Checker()

    if main.debug2:
        main.handle()
    else:
        try:
            main = Checker()
            main.handle()
        except Exception as e:
            logging.debug(e.__class__.__name__)
            exit_with_error(e)
