#!/usr/bin/env python

"""
Nagios/Icinga plugin to monitor virtual machines backups of a Proxmox VE node

authors:
    Mattia Martinello - mattia@mattiamartinello.com
"""

_VERSION = '1.0'
_VERSION_DESCR = 'Monitors virtual machines backups of a Proxmox VE node.'

import argparse
import logging
from proxmoxer import ProxmoxAPI
import sys
import re

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

        # run the workflow and store the results
        self._results = self.handle()

    def add_arguments(self, parser):
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
            choices=['not_backed_up'],
            help='The check to be done:'
                 ' (not_backed_up = virtual machines not backed up '
        )

        parser.add_argument(
            '--debug',
            action="store_true",
            help='Print debugging info to console. This may make the plugin '
                 'not working with Icinga since it prints stuff to console.'
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
            '-e', '--exclude',
            action='append',
            dest='excluded_vmids',
            type=int,
            default=[],
            help='List of VM IDs to be excluded from check'
        )

        parser.add_argument(
            '-l', '--level',
            choices=['warning', 'critical'],
            dest='level',
            default='critical',
            help='The Icinga error level to raise in case of failure'
                 ' (\'not_backed_up\' check only)'
        )

        parser.add_argument(
            '-n', '--node',
            dest='node',
            help='Filter the VMs running on this Proxmox node'
        )

    def _manage_arguments(self, args):
        # positional: check to be done
        self.check = getattr(args, 'check')

        # debug flag
        if getattr(args, 'debug', False):
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

        # excluded VM IDs
        self.excluded_vmids = getattr(args, 'excluded_vmids', [])

        # print arguments (debug)
        logging.debug('Command arguments: {}'.format(args))

        # error level (only in 'not_backed_up' check mode, else exit)
        level = getattr(args, 'level', None)
        if level and self.check != 'not_backed_up':
            exit_with_error('level not allowed on this check mode')
        else:
            self.level = getattr(args, 'level')

        # Proxmox node
        self.node = getattr(args, 'node', None)

    def handle(self):
        # connect to Proxmox and ask for VMs not backed up
        self.proxmox = self._pve_connect()
        

        if self.check == 'not_backed_up':
            self._check_vm_not_backed_up()

        # nothing has failed before, return success
        icinga_exit(ICINGA_OK)

    def _check_vm_not_backed_up(self):
        """Check if there are virtual machines without backup jobs
        """

        # get VMs not backed up
        url = '/cluster/backup-info/not-backed-up'
        not_backed_up = self.proxmox(url).get()
        
        msg = 'VMs not backed up: {}'.format(not_backed_up)
        logging.debug(msg)

        # get virtual machines on selected node if given
        if self.node:
            node_vms = self._get_node_vms(self.node)

        # exclude VMs if requested
        excluded_vmids = list(set(self.excluded_vmids))
        included_vms = []
        if len(excluded_vmids):
            logging.debug('Excluded VM IDs: {}'.format(excluded_vmids))

            for vm in not_backed_up:
                vmid = vm['vmid']

                if vmid not in excluded_vmids:
                    msg = 'Including VM {} ...'.format(vmid)
                    logging.debug(msg)
                    included_vms.append(vm)
        else:
            included_vms = not_backed_up

        # compose perfdata
        not_backed_up_count = len(included_vms)
        perfdata = ['not_backed_up={}'.format(not_backed_up_count)]

        # check included not backed up virtual machines
        if not_backed_up_count > 0:
            if not_backed_up_count == 1:
                plural = ''
            else:
                plural = 's'

            # compose the exit message elements
            elements = []
            for vm in included_vms:
                if vm['type'] == 'qemu':
                    type = 'VM'
                elif vm['type'] == 'lxc':
                    type = 'CT'
                else:
                    type = 'OTHER'

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

    def _pve_connect(self):
        """Connect to Proxmox VE API
        """

        # compose the Proxmox API host (host:port)
        host = '{}:{}'.format(self.host, self.port)

        msg = 'Connecting to Proxmox API at host {} with username {} ...'
        msg = msg.format(host, self.username)
        logging.debug(msg)

        # connect to Proxmox API
        proxmox = ProxmoxAPI(
            host,
            user=self.username,
            password=self.password,
            verify_ssl=self.verify_ssl,
            backend='https',
            service='pve'
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
                node_vms.append({
                    'vmid': vm['vmid'],
                    'name': vm['name'],
                    'type': vm['type']
                })

        vm_count = len(node_vms)
        msg = '{} virtual machines on node {}: {}'
        msg = msg.format(vm_count, node_name, node_vms)
        logging.debug(msg)


if __name__ == "__main__":
    # run the procedure and get results
    main = Checker()
    main.handle()
