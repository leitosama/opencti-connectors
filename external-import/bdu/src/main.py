"""OpenCTI BDU connector main module"""

import time
import sys
import os
import io
from datetime import datetime, timezone
import ssl
import zipfile
import xml.etree.ElementTree as ET

import stix2
import urllib3
import yaml
from pycti import (
    OpenCTIConnectorHelper,
    get_config_variable,
    Identity, Vulnerability
)  # type: ignore



class BDUConnector:
    """
    BDU OpenCTI connector main class
    """
    def __init__(self):
        """
        Initialize the BDUConnector with necessary configurations
        """
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path,'r', encoding='utf-8'), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config, True)
        self.author = self._create_author()

        self.base_url = get_config_variable(
                "BDU_BASE_URL",
                ["bdu", "base_url"],
                config,
                default="https://bdu.fstec.ru/files/documents/vulxml.zip",
            )

        self.verify_cert = bool(
            get_config_variable(
                "BDU_VERIFY_CERT",
                ["bdu", "verify_cert"],
                config,
                default=False,
            )
        )

        self.interval = get_config_variable(
            "BDU_INTERVAL",
            ["bdu", "interval"],
            config,
            isNumber=True,
        )

        self.helper = OpenCTIConnectorHelper(config, True)

    def run(self) -> None:
        """
        Main execution loop procedure for BDU connector
        """
        self.helper.log_info("[CONNECTOR] Fetching datasets...")
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(60)

    def _initiate_work(self, timestamp: int) -> str:
        """
        Initialize a work
        :param timestamp: Timestamp in integer
        :return: Work id in string
        """
        now = datetime.fromtimestamp(timestamp, timezone.utc)
        friendly_name = f"{self.helper.connect_name} run @ " + now.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        info_msg = f"[CONNECTOR] New work '{work_id}' initiated..."
        self.helper.log_info(info_msg)

        return work_id

    def update_connector_state(self, current_time: int, work_id: str) -> None:
        """
        Update the connector state
        :param current_time: Time in int
        :param work_id: Work id in string
        """
        msg = (
            f"[CONNECTOR] Connector successfully run, storing last_run as "
            f"{datetime.fromtimestamp(current_time,tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self.helper.log_info(msg)
        self.helper.api.work.to_processed(work_id, msg)
        self.helper.set_state({"last_run": current_time})

        interval_in_hours = round(self.interval / 60 / 60, 2)
        self.helper.log_info(
            "[CONNECTOR] Last_run stored, next run in: "
            + str(interval_in_hours)
            + " hours"
        )

    @staticmethod
    def _to_stix_bundle(stix_objects):
        """
        :return: STIX objects as a Bundle
        """
        return stix2.Bundle(objects=stix_objects, allow_custom=True)

    @staticmethod
    def _to_json_bundle(stix_bundle):
        """
        :return: STIX bundle as JSON format
        """
        return stix_bundle.serialize()

    def send_bundle(self, work_id: str) -> None:
        """
        Send bundle to API
        :param work_id: work id in string
        :return:
        """
        vulnerabilities_objects = self.create_stix_bundle()

        if len(vulnerabilities_objects) != 0:
            vulnerabilities_objects.append(self.author)
            vulnerabilities_bundle = self._to_stix_bundle(vulnerabilities_objects)
            vulnerabilities_to_json = self._to_json_bundle(vulnerabilities_bundle)

            # Retrieve the author object for the info message
            info_msg = (
                f"[CONVERTER] Sending bundle to server with {len(vulnerabilities_bundle)} objects, "
                f"concerning {len(vulnerabilities_objects) - 1} vulnerabilities"
            )
            self.helper.log_info(info_msg)

            self.helper.send_stix2_bundle(
                vulnerabilities_to_json,
                work_id=work_id,
            )
        else:
            pass

    @staticmethod
    def parse_vector(vector: str) -> dict:
        """Parse CVSS vector and get CIA impact and AV of vulnerability

        Args:
            vector (str): String CVSS vector

        Returns:
            dict: CIA impact and AV of vulnerability in dictonary format
        """
        result = {
            "attack_vector": None,
            "integrity_impact": None,
            "availability_impact": None,
            "confidentiality_impact": None
        }
        parts = vector.split("/")
        for part in parts:
            if part.startswith("AV:"):
                result["attack_vector"] = part.split(":")[1]
            elif part.startswith("I:"):
                result["integrity_impact"] = part.split(":")[1]
            elif part.startswith("A:"):
                result["availability_impact"] = part.split(":")[1]
            elif part.startswith("C:"):
                result["confidentiality_impact"] = part.split(":")[1]
        return result

    @staticmethod
    def _create_author():
        """
        :return: BDU's default author
        """
        return stix2.Identity(
            id=Identity.generate_id("FSTEC", "organization"),
            name="FSTEC",
            identity_class="organization",
        )


    def parse_bdu_vul(self, vul: ET.Element, vul_name:str) -> stix2.Vulnerability:
        """Parse BDU vulnerabilities from XML item to STIX object

        Args:
            vul (xml.etree.ElementTree.Element): ElementTree item with vulnerability
            vul_name (str): Name (ID) of vulnerability

        Returns:
            stix2.Vulnerability: STIX vulnerability object with parsed data
        """
        sev_rus_to_eng = {
            "Критический": "Critical",
            "Высокий": "High",
            "Средний": "Medium",
            "Низкий": "Low",
            "Нет": "Unknown"
        }
        childs = list()
        for child in vul:
            childs.append(child.tag)

        self.helper.log_debug(childs)
        vul_description = vul.find('description').text
        vul_created_str = vul.find('identify_date').text
        if vul_created_str != "Данные уточняются":
            vul_created = datetime.strptime(vul_created_str,"%d.%m.%Y")
        else:
            vul_created = None
        vul_external_references = list()
        vul_identifiers = vul.find('identifiers')
        if vul_identifiers is not None and len(vul_identifiers)!=0:
            for ident in vul_identifiers:
                ref = stix2.ExternalReference(
                    source_name=ident.attrib['type'], external_id=ident.text
                )
                vul_external_references.append(ref)

        vul_severity = sev_rus_to_eng[vul.find('severity').text.split(' ')[0]]

        vul_custom_properties = {
            "x_opencti_base_score": None,
            "x_opencti_base_severity": vul_severity,
            "x_opencti_attack_vector": None,
            "x_opencti_integrity_impact": None,
            "x_opencti_availability_impact": None,
            "x_opencti_confidentiality_impact": None,
        }
        vul_cvss_score = 0
        vul_vector = None

        vul_cvss3 = vul.find('cvss3')
        vul_cvss2 = vul.find('cvss')

        if vul_cvss3 is not None and float(vul_cvss3.find('vector').get('score')) != 0:
            vul_cvss_score = float(vul_cvss3.find('vector').get('score'))
            vul_vector = vul_cvss3.find('vector').text
        else:
            vul_vector = vul_cvss2.find('vector').text
            vul_cvss_score = float(vul_cvss2.find('vector').get('score'))

        vul_custom_properties['x_opencti_base_score'] = vul_cvss_score

        vector_d = BDUConnector.parse_vector(vul_vector)

        for k,v in vector_d.items():
            vul_custom_properties[f'x_opencti_{k}'] = v

        vulnerability_to_stix2 = stix2.Vulnerability(
            name=vul_name,
            id = Vulnerability.generate_id(vul_name),
            created_by_ref=self.author,
            created = vul_created,
            description = vul_description,
            confidence = 100 if vul_description else 60,
            lang = "ru",
            custom_properties = vul_custom_properties,
            external_references = vul_external_references + [stix2.ExternalReference(
                    source_name="bdu", url=f"https://bdu.fstec.ru/vul/{vul_name.split(':')[1]}")])

        return vulnerability_to_stix2



    def create_stix_bundle(self) -> list:
        """
        Retrieve all BDU from FSTEC to convert into STIX2 format
        :return: List of data converted into STIX2
        """
        # Create a pool manager
        http = None
        if self.verify_cert:
            http = urllib3.PoolManager()
        else:
            http = urllib3.PoolManager(
                cert_reqs='CERT_NONE',
                ssl_context=ssl._create_unverified_context()
            )

        # Download the zip file
        response = http.request('GET', self.base_url)
        bduxml = None
        if response.status != 200:
            raise ValueError(f"Failed to download BDU File, status code: {response.status}")
        # Read the zip file content into a BytesIO object
        zip_file_content = io.BytesIO(response.data)

        # Open the zip file
        with zipfile.ZipFile(zip_file_content) as zip_file:
            with zip_file.open('export/export.xml') as file:
                bduxml = file.read()  # Read file content

        xmlroot = ET.fromstring(bduxml)
        self.helper.log_debug(f"BDU vulns count: {len(xmlroot)}")
        stix_bundle = []
        for vul in xmlroot:
            name = vul.find('identifier').text
            self.helper.log_debug(f"Parsing {name}")
            vulnerability_to_stix2 = None
            try:
                vulnerability_to_stix2 = self.parse_bdu_vul(vul,name)
            except:
                self.helper.log_error(f"Can't parse {name}")
                continue
            stix_bundle.append(vulnerability_to_stix2)
            # TODO: it's a break for debug, Frodo
            # break
        return stix_bundle

    def process_data(self) -> None:
        """
        Main process of connector
        """
        try:
            # Get the current state and check if connector already runs
            now = datetime.now()
            current_time = int(datetime.timestamp(now))
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]

                msg = "[CONNECTOR] Connector last run: " + datetime.fromtimestamp(
                    last_run, timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S")
                self.helper.log_info(msg)
            else:
                last_run = None
                msg = "[CONNECTOR] Connector has never run..."
                self.helper.log_info(msg)

            # Main process if connector successfully works
            work_id = self._initiate_work(current_time)
            self.send_bundle(work_id)

            self.update_connector_state(current_time, work_id)

            time.sleep(5)

        except (KeyboardInterrupt, SystemExit):
            msg = "[CONNECTOR] Connector stop..."
            self.helper.log_info(msg)
            sys.exit(0)
        except Exception as e:
            error_msg = f"[CONNECTOR] Error while processing data: {str(e)}"
            self.helper.log_error(error_msg)



if __name__ == "__main__":
    try:
        connector = BDUConnector()
        connector.run()
    except Exception as err:
        print(err)
        time.sleep(10)
        exit(-1)
