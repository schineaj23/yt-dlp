from .common import PostProcessor
from ..utils import PostProcessingError
from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH
import requests

class WidevineDecryptPP(PostProcessor):
    def __init__(self, downloader, device=None, pssh=None):
        super().__init__(downloader)
        self.device_path = device
        if self.device_path is None:
            raise PostProcessingError('Widevine decryption requires a device path to be specified. ' \
            'Please provide a valid device path.')
        self.pssh = pssh
        if self.pssh is None:
            raise PostProcessingError('Widevine decryption requires a PSSH to be specified. ' \
            'Please provide a valid PSSH.')
    def run(self, info):
        self.report_warning('Widevine decryption is not fully supported yet. ' \
        'Please report any issues you encounter.')
        license_url = info.get('_license_url')
        license_auth_token = info.get('_license_auth_token')

        self.write_debug(f'Widevine PSSH: {self.pssh}')
        self.write_debug(f'Widevine License URL: {license_url}')
        self.write_debug(f'Widevine License Auth Token: {license_auth_token}')

        formats_to_decrypt = info.get('requested_formats') or [info]
        for fmt in formats_to_decrypt:
            encrypted_filepath = fmt.get('filepath')
            if not encrypted_filepath:
                self.report_warning(f'No filepath {encrypted_filepath} found for format {fmt.get("format")}, skipping decryption.')
                continue
            try:
                self.write_debug(f'Attempting to decrypt {encrypted_filepath}')
                pssh = PSSH(self.pssh)
                device = Device.load(self.device_path)
                cdm = Cdm.from_device(device)
                session_id = cdm.open()
                challenge = cdm.get_license_challenge(session_id, pssh)
                license = requests.post(license_url, data=challenge)
                license.raise_for_status()
                cdm.parse_license(session_id, license.content)
                cdm.decrypt(session_id, encrypted_filepath, encrypted_filepath, exists_ok=True)
                cdm.close(session_id)
            except Exception as e:
                raise PostProcessingError(f'Failed to decrypt fragment: {e}')
        return [], info