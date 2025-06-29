# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2016 Red Hat, Inc.
# All rights reserved.
#

import argparse
import inspect
import io
import logging
import os
import shutil
import sys
import tempfile
import textwrap
import urllib.parse

import pki.cli
import pki.server.cli.audit
import pki.server.cli.config
import pki.server.cli.db
import pki.server.cli.group
import pki.server.cli.subsystem
import pki.server.cli.user

logger = logging.getLogger(__name__)


class TPSCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('tps', 'TPS management commands')

        self.add_module(pki.server.cli.subsystem.SubsystemCreateCLI(self))
        self.add_module(pki.server.cli.subsystem.SubsystemDeployCLI(self))
        self.add_module(pki.server.cli.subsystem.SubsystemUndeployCLI(self))
        self.add_module(pki.server.cli.subsystem.SubsystemRedeployCLI(self))
        self.add_module(pki.server.cli.audit.AuditCLI(self))
        self.add_module(TPSCloneCLI())
        self.add_module(TPSConnectorCLI())
        self.add_module(pki.server.cli.config.SubsystemConfigCLI(self))
        self.add_module(pki.server.cli.db.SubsystemDBCLI(self))
        self.add_module(pki.server.cli.group.GroupCLI(self))
        self.add_module(pki.server.cli.user.UserCLI(self))


class TPSCloneCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('clone', 'TPS clone management commands')

        self.add_module(TPSClonePrepareCLI())


class TPSClonePrepareCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('prepare', 'Prepare TPS clone')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--pkcs12-file')
        self.parser.add_argument('--pkcs12-password')
        self.parser.add_argument('--pkcs12-password-file')
        self.parser.add_argument(
            '--no-key',
            action='store_true')
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '--help',
            action='store_true')

    def print_help(self):
        print('Usage: pki-server tps-clone-prepare [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --pkcs12-file <path>           PKCS #12 file to store certificates and keys.')
        print('      --pkcs12-password <password>   Password for the PKCS #12 file.')
        print('      --pkcs12-password-file <path>  File containing the PKCS #12 password.')
        print('      --no-key                       Do not include private key.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance
        pkcs12_file = args.pkcs12_file

        pkcs12_password = None

        if args.pkcs12_password:
            pkcs12_password = args.pkcs12_password.encode()

        if args.pkcs12_password_file:
            with io.open(args.pkcs12_password_file, 'rb') as f:
                pkcs12_password = f.read()

        no_key = args.no_key

        if not pkcs12_file:
            logger.error('Missing PKCS #12 file')
            self.print_help()
            sys.exit(1)

        if not pkcs12_password:
            logger.error('Missing PKCS #12 password')
            self.print_help()
            sys.exit(1)

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)
        instance.load()

        subsystem = instance.get_subsystem('tps')
        if not subsystem:
            logger.error('No TPS subsystem in instance %s.', instance_name)
            sys.exit(1)

        tmpdir = tempfile.mkdtemp()

        try:
            pkcs12_password_file = os.path.join(tmpdir, 'pkcs12_password.txt')
            with open(pkcs12_password_file, 'wb') as f:
                f.write(pkcs12_password)

            subsystem.export_system_cert(
                'subsystem', pkcs12_file, pkcs12_password_file, no_key=no_key)

            # audit signing cert is optional
            cert = subsystem.get_subsystem_cert('audit_signing')

            # export audit signing cert if available (i.e. has nickname)
            if cert['nickname']:
                subsystem.export_system_cert(
                    'audit_signing',
                    pkcs12_file,
                    pkcs12_password_file,
                    no_key=no_key,
                    append=True)

            instance.export_external_certs(
                pkcs12_file, pkcs12_password_file, append=True)

        finally:
            shutil.rmtree(tmpdir)


class TPSConnectorCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('connector', 'TPS connector management commands')

        self.add_module(TPSConnectorFindCLI())
        self.add_module(TPSConnectorAddCLI())

    @staticmethod
    def print_connector(connector, show_all=False):

        connector_id = connector.get('id')
        print('  Connector ID: {}'.format(connector_id))

        connector_type = connector.get('type')
        print('  Type: {}'.format(connector_type))

        enabled = connector.get('enabled')
        print('  Enabled: {}'.format(enabled))

        url = connector.get('url')
        print('  URL: {}'.format(url))

        nickname = connector.get('nickname')
        print('  Nickname: {}'.format(nickname))

        if not show_all:
            return

        minConns = connector.get('minConns')
        if minConns:
            print('  Min connections: {}'.format(minConns))

        maxConns = connector.get('maxConns')
        if maxConns:
            print('  Max connections: {}'.format(maxConns))

        timeout = connector.get('timeout')
        if timeout:
            print('  Timeout: {}'.format(timeout))


class TPSConnectorFindCLI(pki.cli.CLI):
    '''
    Find TPS connectors
    '''

    help = '''\
        Usage: pki-server tps-connector-find [OPTIONS]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --show-all                     Show all attributes.
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''  # noqa: E501

    def __init__(self):
        super().__init__('find', inspect.cleandoc(self.__class__.__doc__))

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--show-all',
            action='store_true')
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '--help',
            action='store_true')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('tps')

        if not subsystem:
            logger.error('No TPS subsystem in instance %s', instance_name)
            sys.exit(1)

        first = True

        for connector in subsystem.get_connectors():

            if first:
                first = False
            else:
                print()

            TPSConnectorCLI.print_connector(connector, args.show_all)


class TPSConnectorAddCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('add', 'Add TPS connector')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--type')
        self.parser.add_argument('--url')
        self.parser.add_argument('--nickname')
        self.parser.add_argument(
            '--keygen',
            action='store_true')
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '--help',
            action='store_true')
        self.parser.add_argument(
            'connector_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server tps-connector-add [OPTIONS] <connector ID>')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat)')
        print('      --type <type>                  Connector type: CA, KRA, TKS')
        print('      --url <URL>                    Subsystem URL')
        print('      --nickname <nickname>          Certificate nickname')
        print('      --keygen                       Enable server-side key generation')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance
        connector_id = args.connector_id
        connector_type = args.type
        url = urllib.parse.urlparse(args.url)
        nickname = args.nickname
        keygen = args.keygen

        if connector_id is None:
            raise pki.cli.CLIException('Missing connector ID')

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('tps')

        if not subsystem:
            logger.error('No TPS subsystem in instance %s', instance_name)
            sys.exit(1)

        subsystem.add_connector(
            connector_id=connector_id,
            connector_type=connector_type,
            url=url,
            nickname=nickname,
            keygen=keygen)

        subsystem.save()
