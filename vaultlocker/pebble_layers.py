# -*- coding: utf-8 -*-

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Boot-time unlock via Pebble layers for the snap distribution.

A strictly confined snap cannot write or enable arbitrary host systemd
template-unit instances at runtime, so the snap runs Pebble as its
supervised init process (``daemon: simple``) and registers one Pebble
service per managed device. Pebble's children run inside the same
confinement context as any other snap app, so the ``dm-crypt`` and
``block-devices`` interfaces continue to apply.
"""

import logging
import os
import re
import subprocess
import textwrap

logger = logging.getLogger(__name__)

#: Pebble CLI binary installed alongside the snap.
PEBBLE_BINARY = 'pebble'

#: Environment variable pointing at the Pebble configuration directory.
PEBBLE_DIR_ENV_VAR = 'PEBBLE'

#: Pebble's default configuration directory.
DEFAULT_PEBBLE_DIR = '/var/lib/pebble/default'

#: Prefix for the Pebble layer label for each managed device.
LAYER_LABEL_PREFIX = 'vaultlocker-decrypt-'

#: Name of the directory Pebble loads layer files from.
LAYERS_DIR_NAME = 'layers'

#: First numeric prefix used for per-device layer files. Pebble orders
#: layers by this prefix and requires a unique prefix per layer file.
LAYER_PREFIX_START = 100

#: Regular expression matching the numeric prefix of a layer filename.
LAYER_PREFIX_PATTERN = re.compile(r'^(\d+)-')

#: Delays controlling Pebble's restart backoff for an unlock service.
BACKOFF_DELAY = '5s'
BACKOFF_LIMIT = '30s'


def pebble_dir():
    """Return the Pebble configuration directory for this environment.

    :returns: str. Pebble directory path.
    """
    return os.environ.get(PEBBLE_DIR_ENV_VAR) or DEFAULT_PEBBLE_DIR


def layer_label(block_uuid):
    """Return the Pebble layer label for a managed device.

    :param: block_uuid: UUID of the encrypted block device.
    :returns: str. Pebble layer label.
    """
    return '{}{}'.format(LAYER_LABEL_PREFIX, block_uuid)


def service_name(block_uuid):
    """Return the Pebble service name for a managed device.

    :param: block_uuid: UUID of the encrypted block device.
    :returns: str. Pebble service name.
    """
    return 'decrypt-{}'.format(block_uuid)


def render_layer(block_uuid, config_path, timeout):
    """Render the Pebble layer YAML for a managed device.

    The service retries on failure so that a temporarily unavailable
    Vault does not leave the device permanently locked, matching the
    systemd-based behaviour used outside the snap.

    :param: block_uuid: UUID of the encrypted block device.
    :param: config_path: Path to the vaultlocker configuration file.
    :param: timeout: Seconds to retry connecting to Vault.
    :returns: str. Pebble layer YAML.
    """
    command = (
        'vaultlocker --retry {timeout} --config {config} '
        'decrypt {uuid}'
    ).format(
        timeout=timeout,
        config=config_path,
        uuid=block_uuid,
    )
    return textwrap.dedent(
        """\
        services:
          {service}:
            override: replace
            command: {command}
            startup: enabled
            on-success: ignore
            on-failure: restart
            backoff-delay: {backoff_delay}
            backoff-limit: {backoff_limit}
        """
    ).format(
        service=service_name(block_uuid),
        command=command,
        backoff_delay=BACKOFF_DELAY,
        backoff_limit=BACKOFF_LIMIT,
    )


def _existing_layer_path(layers_dir, label):
    """Return the path of an existing layer file for a label, if any.

    :param: layers_dir: Pebble layers directory.
    :param: label: Pebble layer label.
    :returns: str path, or None.
    """
    suffix = '-{}.yaml'.format(label)
    for name in os.listdir(layers_dir):
        if name.endswith(suffix):
            return os.path.join(layers_dir, name)
    return None


def _next_layer_prefix(layers_dir):
    """Return the next unused numeric layer prefix.

    Pebble orders layers by a unique numeric filename prefix.

    :param: layers_dir: Pebble layers directory.
    :returns: int. Next prefix.
    """
    highest = LAYER_PREFIX_START - 1
    for name in os.listdir(layers_dir):
        match = LAYER_PREFIX_PATTERN.match(name)
        if match:
            highest = max(highest, int(match.group(1)))
    return highest + 1


def _layer_path(layers_dir, label):
    """Return the persistent layer path for a device label.

    Reuses the existing file for the label (so a rewrite replaces it) and
    otherwise allocates a new unique numeric prefix.

    :param: layers_dir: Pebble layers directory.
    :param: label: Pebble layer label.
    :returns: str. Layer file path.
    """
    existing = _existing_layer_path(layers_dir, label)
    if existing is not None:
        return existing

    prefix = _next_layer_prefix(layers_dir)
    return os.path.join(
        layers_dir, '{:03d}-{}.yaml'.format(prefix, label),
    )


def register_boot_unlock(block_uuid, config_path, timeout):
    """Register a Pebble service to unlock a managed device at boot.

    The layer is written to Pebble's persistent layers directory so it is
    picked up on every Pebble start (including host boot). The plan is
    then replanned so the service is scheduled immediately.

    :param: block_uuid: UUID of the encrypted block device.
    :param: config_path: Path to the vaultlocker configuration file.
    :param: timeout: Seconds to retry connecting to Vault.
    """
    label = layer_label(block_uuid)
    layer = render_layer(block_uuid, config_path, timeout)

    layers_dir = os.path.join(pebble_dir(), LAYERS_DIR_NAME)
    os.makedirs(layers_dir, exist_ok=True)
    layer_path = _layer_path(layers_dir, label)
    temporary_path = '{}.tmp'.format(layer_path)

    logger.info('Writing Pebble unlock layer %s', layer_path)
    with open(temporary_path, 'w', encoding='utf-8') as layer_file:
        layer_file.write(layer)
    os.replace(temporary_path, layer_path)

    try:
        subprocess.run(
            [PEBBLE_BINARY, 'replan'],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as replan_error:
        # The unlock command is one-shot: after a successful unlock it
        # exits, which Pebble reports as a failed start even though the
        # layer and service state are correct. Pebble keeps the service
        # scheduled and retries failures, so this is not fatal here.
        logger.warning(
            'pebble replan reported an error after registering %s (%s); '
            'the unlock service remains scheduled',
            label,
            replan_error,
        )
