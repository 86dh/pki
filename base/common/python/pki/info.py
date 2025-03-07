# This program is free software; you can redistribute it and/or modify
# it under the terms of the Lesser GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2013 Red Hat, Inc.
# All rights reserved.
#
# Author:
#     Ade Lee <alee@redhat.com>
#
"""
Module containing the Python client classes for the InfoClient
"""

import inspect
import json
import logging
import requests.exceptions

from six import iteritems

import pki

logger = logging.getLogger(__name__)


class Info(object):
    """
    This class encapsulates the parameters returned by the server's
    InfoService.
    """

    json_attribute_names = {
        'Version': 'version',
        'Banner': 'banner'
    }

    def __init__(self, version=None, banner=None):
        """ Constructor """
        self.version = version
        self.banner = banner

    @classmethod
    def from_json(cls, attr_list):
        """ Return Info from JSON dict """
        info = cls()
        for k, v in iteritems(attr_list):
            if k in Info.json_attribute_names:
                setattr(info, Info.json_attribute_names[k], v)
            else:
                setattr(info, k, v)
        return info


class Version(tuple):
    __slots__ = ()

    def __new__(cls, version):
        parts = [int(p) for p in version.split('.')]
        if len(parts) < 3:
            parts.extend([0] * (3 - len(parts)))
        if len(parts) > 3:
            raise ValueError(version)
        return tuple.__new__(cls, tuple(parts))

    def __str__(self):
        return '{}.{}.{}'.format(*self)

    def __repr__(self):
        return "<Version('{}.{}.{}')>".format(*self)

    def __getnewargs__(self):
        # pickle support
        return (str(self),)

    @property
    def major(self):
        return self[0]

    @property
    def minor(self):
        return self[1]

    @property
    def patchlevel(self):
        return self[2]


class InfoClient(object):
    """
    Class encapsulating and mirroring the functionality in the
    InfoResource Java interface class defining the REST API for
    server Info resources.
    """

    def __init__(self, parent):
        """ Constructor """

        if isinstance(parent, pki.client.PKIConnection):

            logger.warning(
                '%s:%s: The PKIConnection parameter in InfoClient.__init__() has been deprecated. '
                'Provide PKIClient instead.',
                inspect.stack()[1].filename, inspect.stack()[1].lineno)

            self.pki_client = None
            self.connection = parent

        else:
            self.pki_client = parent
            self.connection = self.pki_client.connection

    @pki.handle_exceptions()
    def get_info(self):
        """ Return an Info object form a PKI server """

        if self.pki_client and self.pki_client.api_path:
            # use REST API path specified in PKIClient
            api_paths = [self.pki_client.api_path]

        else:
            # try all possible REST API paths
            api_paths = ['v2', 'rest']

        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}

        response = None

        for api_path in api_paths:
            try:
                path = '/pki/%s/info' % api_path
                logger.info('Getting PKI server info from %s', path)

                response = self.connection.get(path, headers)
                # REST API path available -> done
                break

            except requests.exceptions.HTTPError as e:
                if e.response.status_code != 404:
                    raise
                # REST API path not available -> try another

        if not response:
            raise Exception('Unable to get PKI server info')

        json_response = response.json()
        logger.debug('Response:\n%s', json.dumps(json_response, indent=4))

        return Info.from_json(json_response)

    @pki.handle_exceptions()
    def get_version(self):
        """ return Version object from server """
        version_string = self.get_info().version
        return Version(version_string)


if __name__ == '__main__':
    print(Version('10'))
    print(Version('10.1'))
    print(Version('10.1.1'))
    print(tuple(Version('10.1.1')))
    print(Version('10.1.1.1'))
