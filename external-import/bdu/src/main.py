"""OpenCTI BDU connector main module"""

import time
import sys
import os
import io
import yaml
import time
import ssl
import urllib3
import zipfile
import stix2
from cvss import CVSS3
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta


from pycti import (
    STIX_EXT_OCTI,
    STIX_EXT_OCTI_SCO,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
    get_config_variable,
    Identity, StixCoreRelationship, Vulnerability
)  # type: ignore



class BDUConnector:
    def __init__(self):
        """
        Initialize the BDUConnector with necessary configurations
        """
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config, True)
        self.author = self._create_author()

        # bdu:
            # base_url: 'https://bdu.fstec.ru/files/documents/vulxml.zip' # Required
            # verify_cert: False
            # interval: 6 # Required, in hours advice min 2`

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
        # self.converter = BDUConnector(self.helper)

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
        now = datetime.utcfromtimestamp(timestamp)
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
            f"{datetime.utcfromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S')}"
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
        vulnerabilities_objects = self.vulnerabilities_to_stix2()

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


    def parse_bdu_vul(self, vul) -> stix2.Vulnerability:
        external_refs = list()
        vector = None
        # Getting different fields
        for vul_param in vul:
            if vul_param.tag == "identifier":
                name = vul_param.text
            elif vul_param.tag == "description":
                description = vul_param.text
            elif vul_param.tag == "identify_date":
                created_date = datetime.strptime(vul_param.text,"%d.%m.%Y")
            elif vul_param.tag == "identifiers":
                external_refs = list()
                for ident in vul_param:
                    ref = stix2.ExternalReference(
                        source_name=ident.attrib['type'], external_id=ident.text
                    )
                    external_refs.append(ref)
            elif vul_param.tag == "severity":
                severity = vul_param.text
            elif vul_param.tag == "cvss3" and not vector:
                for cvss_param in vul_param:
                    if cvss_param.tag == "vector":
                        vector = cvss_param.text
                        base_score = float(cvss_param.attrib['score'])
            elif vul_param.tag == "cvss" and not vector:
                for cvss_param in vul_param:
                    if cvss_param.tag == "vector":
                        vector = cvss_param.text
                        base_score = float(cvss_param.attrib['score'])
        # Create external references
        bdu_id = name.split(':')[1]
        # self.helper.log_debug(bdu_id)
        external_reference = stix2.ExternalReference(
            source_name="bdu", url=f"https://bdu.fstec.ru/vul/{bdu_id}"
        )
        external_references = [external_reference] + external_refs
        # self.helper.log_debug(vector)
        vector_d = BDUConnector.parse_vector(vector)

        attack_vector = vector_d["attack_vector"]
        availability_impact = vector_d["availability_impact"]
        base_score = base_score
        base_severity = severity
        confidentiality_impact = vector_d["confidentiality_impact"]
        integrity_impact = vector_d["integrity_impact"]

        # Creating the vulnerability with the extracted fields
        vulnerability_to_stix2 = stix2.Vulnerability(
            id=Vulnerability.generate_id(name),
            name=name,
            created=created_date,
            description=description,
            created_by_ref=self.author,
            confidence=(
                100 if description is not None and len(description) > 0 else 60
            ),
            external_references=external_references,
            custom_properties={
                "x_opencti_base_score": base_score,
                "x_opencti_base_severity": base_severity,
                "x_opencti_attack_vector": attack_vector,
                "x_opencti_integrity_impact": integrity_impact,
                "x_opencti_availability_impact": availability_impact,
                "x_opencti_confidentiality_impact": confidentiality_impact,
            },
        )
        return vulnerability_to_stix2



    def vulnerabilities_to_stix2(self) -> list:
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
        # with zipfile.ZipFile("/tmp/vulxml.zip") as zip_file:
        #     with zip_file.open('export/export.xml') as file:
        #         bduxml = file.read()  # Read file content



        
        
        xmlroot = ET.fromstring(bduxml)
        
        vulnerabilities_to_stix2 = []
        for vul in xmlroot:
            name = None
            for vul_param in vul:
                if vul_param.tag == "identifier":
                    name = vul_param.text
            vulnerability_to_stix2 = None
            try:
                vulnerability_to_stix2 = self.parse_bdu_vul(vul)
            except:
                self.helper.log_debug(f"Can't parse {name}")
                continue
            vulnerabilities_to_stix2.append(vulnerability_to_stix2)
            break
        return vulnerabilities_to_stix2

    def process_data(self) -> None:
        try:
            """
            Get the current state and check if connector already runs
            """
            now = datetime.now()
            current_time = int(datetime.timestamp(now))
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]

                msg = "[CONNECTOR] Connector last run: " + datetime.utcfromtimestamp(
                    last_run
                ).strftime("%Y-%m-%d %H:%M:%S")
                self.helper.log_info(msg)
            else:
                last_run = None
                msg = "[CONNECTOR] Connector has never run..."
                self.helper.log_info(msg)

            """
            ======================================================
            Main process if connector successfully works
            ======================================================
            """
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
    """
    Entry point of the script
    """
    try:
        connector = BDUConnector()
        connector.run()
    except Exception as err:
        print(err)
        time.sleep(10)
        exit(-1)
