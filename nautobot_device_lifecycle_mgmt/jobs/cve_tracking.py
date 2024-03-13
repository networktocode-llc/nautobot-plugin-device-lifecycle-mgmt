# pylint: disable=logging-not-lazy, consider-using-f-string
"""Jobs for the CVE Tracking portion of the Device Lifecycle plugin."""
import os
import re
import json

from datetime import datetime, date
from time import sleep

from urllib3.util import Retry
import requests
from requests import Session
from requests.adapters import HTTPAdapter

from django.core.exceptions import ValidationError
from nautobot.extras.jobs import Job, StringVar
from nautobot.extras.models import Relationship, RelationshipAssociation
from nautobot.dcim.models import Platform
from nautobot_device_lifecycle_mgmt.models import (
    CVELCM,
    SoftwareLCM,
    VulnerabilityLCM,
)
from netutils.platform_mapper import os_platform_object_builder as object_builder

name = "CVE Tracking"  # pylint: disable=invalid-name


class GenerateVulnerabilities(Job):
    """Generates VulnerabilityLCM objects based on CVEs that are related to Devices."""

    name = "Generate Vulnerabilities"
    description = "Generates any missing Vulnerability objects."
    read_only = False
    published_after = StringVar(
        regex=r"^[0-9]{4}\-[0-9]{2}\-[0-9]{2}$",
        label="CVEs Published After",
        description="Enter a date in ISO Format (YYYY-MM-DD) to only process CVEs published after that date.",
        default="1970-01-01",
        required=False,
    )
    # debug = BooleanVar(description="Enable for more verbose logging.")

    class Meta:
        """Meta class for the job."""

        has_sensitive_variables = False
        field_order = [
            "published_after",
            "_task_queue",
            "debug",
        ]

    def run(self, published_after, debug=False):  # pylint: disable=too-many-locals, arguments-differ
        """Check if software assigned to each device is valid. If no software is assigned return warning message."""
        # Although the default is set on the class attribute for the UI, it doesn't default for the API
        published_after = published_after or "1970-01-01"
        cves = CVELCM.objects.filter(published_date__gte=datetime.fromisoformat(published_after))
        count_before = VulnerabilityLCM.objects.count()

        device_soft_rel = Relationship.objects.get(key="device_soft")
        inv_item_soft_rel = Relationship.objects.get(key="inventory_item_soft")

        for cve in cves:
            if debug:
                self.logger.info(
                    "Generating vulnerabilities for CVE %s" % cve,
                    extra={"object": cve},
                )
            for software in cve.affected_softwares.all():
                # Loop through any device relationships
                device_rels = software.get_relationships()["source"][device_soft_rel]
                for dev_rel in device_rels:
                    VulnerabilityLCM.objects.get_or_create(cve=cve, software=dev_rel.source, device=dev_rel.destination)

                # Loop through any inventory tem relationships
                item_rels = software.get_relationships()["source"][inv_item_soft_rel]
                for item_rel in item_rels:
                    VulnerabilityLCM.objects.get_or_create(
                        cve=cve, software=item_rel.source, inventory_item=item_rel.destination
                    )

        diff = VulnerabilityLCM.objects.count() - count_before
        self.logger.info("Processed %d CVEs and generated %d Vulnerabilities." % (cves.count(), diff))

class NistCveSyncSoftware(Job):
    """Checks all software in the DLC Plugin for NIST recorded vulnerabilities."""

    name = "NIST - Software CVE Search"
    description = "Searches the NIST DBs for CVEs related to software"
    read_only = False

    class Meta:  # pylint: disable=too-few-public-methods
        """Meta class for the job."""

        commit_default = True

    def __init__(self):
        """Initializing job with extra options."""
        super().__init__()
        self.nist_api_key = os.getenv("NIST_API_KEY")
        self.sleep_timer = 0.75
        self.headers = {
            "ContentType": "application/json", 
            "apiKey": self.nist_api_key
        }
        
        self.soft_time_limit = 900

        # Set session attributes for retries
        self.session = Session()
        retries = Retry(
            total=3,
            backoff_factor=10,
            status_forcelist=[502, 503, 504],
            allowed_methods={'GET'},
        )
        self.session.mount('https://', HTTPAdapter(max_retries=retries))

    def run(self):
        """Check all software in DLC against NIST database and associate registered CVEs.  Update when necessary."""
        cve_counter = 0
        
        for software in SoftwareLCM.objects.all():
            manufacturer = str(software.device_platform.manufacturer).lower()
            platform = str(software.device_platform.name).lower()
            version = str(software.version)

            cpe_software_search_urls = self.create_cpe_software_search_urls(manufacturer, platform, version)

            self.logger.info(
                f"""Gathering CVE Information for Version: {version}""", 
                extra={
                    "object": software.device_platform, 
                    "grouping": "CVE Information"
                }
            )
            
            software_cve_info = self.get_cve_info(cpe_software_search_urls, software.id)
            all_software_cve_info = {**software_cve_info['new'], **software_cve_info['existing']}

            cve_counter += len(software_cve_info['new'])
            self.create_dlc_cves(software_cve_info['new'])
        
            for software_cve, cve_info in all_software_cve_info.items():
                matching_dlc_cve = CVELCM.objects.get(name=software_cve)
                self.associate_software_to_cve(software.id, matching_dlc_cve.id)
                if str(cve_info['modified_date'][0:10]) != str(matching_dlc_cve.last_modified_date):
                    self.update_cve(matching_dlc_cve, cve_info)
                    continue

        self.logger.info(
            f"""Performed discovery on all software. Created {cve_counter} CVE.""",
            extra={"grouping": "CVE Creation"}
        )
        self.session.close()


    def associate_software_to_cve(self, software_id, cve_id):
        """A function to associate software to a CVE."""
        cve = CVELCM.objects.get(id=cve_id)
        software = SoftwareLCM.objects.get(id=software_id)

        try:
            cve.affected_softwares.add(software)

        except Exception as err:
            self.logger.error(
                f"Unable to create association between CVE and Software Version.  ERROR: {err}",
                extra={
                    "object": cve, 
                    "grouping": "CVE Association"
                }    
            )


    def create_cpe_software_search_urls(self, vendor: str, platform: str, version: str) -> list:
        """Uses netutils.platform_mapper to construct proper search URLs.

        Args:
            vendor (str): Software Vendor (Examples: Cisco, Juniper, Arista)
            platform (str): Software Platform (Examples: IOS, JunOS, EOS)
            version (str): Software Version

        Returns:
            list: List of URLS that associated CVEs may be found
        """
        platform_object = object_builder(vendor, platform, version)
        cpe_urls = platform_object.get_nist_urls()

        return  cpe_urls


    def create_dlc_cves(self, cpe_cves: dict) -> None:
        """Create the list of needed items and insert into to DLC CVEs."""

        created_count = 0

        for cve, info in cpe_cves.items():
            try:
                description = (
                    f"{info['description'][0:251]}..." if len(info["description"]) > 255 else info["description"]
                )
            except TypeError:
                description = "No Description Provided from NIST DB."

            create_cves, created = CVELCM.objects.get_or_create(  # pylint: disable=unused-variable
                name=cve,
                description=description,
                published_date=date.fromisoformat(info.get("published_date", "1900-01-01")[0:10]),
                last_modified_date=date.fromisoformat(info.get("modified_date", "1900-01-01")[0:10]),
                link=info["url"],
                cvss=info["cvss_base_score"],
                severity=info["cvss_severity"],
                cvss_v2=info["cvssv2_score"],
                cvss_v3=info["cvssv3_score"],
                comments="ENTRY CREATED BY NAUTOBOT NIST JOB",
            )

            if created:
                created_count += 1

        self.logger.info(f"Created { created_count } CVEs.", extra={"grouping": "CVE Creation"})


    def get_cve_info(self, cpe_software_search_urls: list, software_id=None) -> dict:
        """Search NIST for software and related CVEs."""
        all_cve_info = {
            'new': {},
            'existing': {}
        }
        for cpe_software_search_url in cpe_software_search_urls:                    
            result = self.query_api(cpe_software_search_url)

            if result["totalResults"] > 0:
                self.logger.info(
                    f"""Received {result['totalResults']} results.""", 
                    extra={
                        "object": SoftwareLCM.objects.get(id=software_id), 
                        "grouping": "CVE Creation"
                    }
                )
                cve_list = [cve['cve'] for cve in result['vulnerabilities']]
                dlc_cves = [cve.name for cve in CVELCM.objects.all()]

                if cve_list:
                    for cve in cve_list:
                        cve_name = cve['id']
                        if cve_name.startswith("CVE"):
                            if cve_name not in dlc_cves:
                                all_cve_info['new'].update({cve_name: self.prep_cve_for_dlc(cve)})
                            else:
                                all_cve_info['existing'].update({cve_name: self.prep_cve_for_dlc(cve)})
                    self.logger.info(
                        f"Prepared { len(all_cve_info['new']) } CVE for creation.", 
                        extra={
                            "object": SoftwareLCM.objects.get(id=software_id), 
                            "grouping": "CVE Creation"
                        }
                    )

        return all_cve_info


    def query_api(self, url):
        try:
            result = self.session.get(url, headers=self.headers)
            result.raise_for_status()
        except requests.exceptions.HTTPError as err:
            code = err.response.status_code
            self.logger.error(f"The NIST Service is currently unavailable. Status Code: {code}. Try running the job again later.")
    
        return result.json()

    @staticmethod
    def convert_v2_base_score_to_severity(score: float) -> str:
        if (score >= 0.0) and (score <= 3.9):
            return "LOW"
        elif (score >= 4.0) and (score <= 6.9):
            return "MEDIUM"
        elif (score >= 7.0) and (score <= 10):
            return "HIGH"
        else:
            return "UNDEFINED"
        
    def prep_cve_for_dlc(self, cve_json):  # pylint: disable=too-many-locals
        """Converts CVE info into DLC Model compatibility."""
        
        cve = cve_json

        # cve_base = cve["vulnerabilities"][0]['cve']
        cve_base = cve
        cve_name = cve_base['id']
        for desc in cve_base['descriptions']:
            if desc['lang'] == 'en':
                cve_description = desc['value']
        cve_published_date = cve_base.get("published")
        cve_modified_date = cve_base.get("lastModified")
        cve_impact = cve_base['metrics']

        # Determine URL
        if len(cve_base["references"]) > 0:
            cve_url = cve_base["references"][0].get(
                "url", f"https://www.cvedetails.com/cve/{cve_name}/"
            )
        else:
            cve_url = f"https://www.cvedetails.com/cve/{cve_name}/"

        # Determine if V3 exists and set all params based on found version info
        if cve_impact.get("cvssMetricV31"):
            cvss_base_score = cve_impact["cvssMetricV31"][0]["cvssData"]["baseScore"]
            cvss_severity = cve_impact["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            if cve_impact.get("cvssMetricV2"):
                cvssv2_score = cve_impact["cvssMetricV2"][0].get("exploitabilityScore", 10)
            else:
                cvssv2_score = 10
            cvssv3_score = cve_impact["cvssMetricV31"][0].get("exploitabilityScore", 10)

        elif cve_impact.get("cvssMetricV30"):
            cvss_base_score = cve_impact["cvssMetricV30"][0]["cvssData"]["baseScore"]
            cvss_severity = cve_impact["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
            if cve_impact.get("cvssMetricV2"):
                cvssv2_score = cve_impact["cvssMetricV2"][0].get("exploitabilityScore", 10)
            else:
                cvssv2_score = 10
            cvssv3_score = cve_impact["cvssMetricV30"][0].get("exploitabilityScore", 10)
            
        else:
            cvss_base_score = cve_impact["cvssMetricV2"][0]["cvssData"]["baseScore"]
            cvss_severity = cve_impact["cvssMetricV2"][0]["baseSeverity"] or self.convert_v2_base_score_to_severity(cvss_base_score)
            cvssv2_score = cve_impact["cvssMetricV2"][0].get("exploitabilityScore", 10)
            cvssv3_score = 0


        all_cve_info = {
            "url": cve_url,
            "description": cve_description,
            "published_date": cve_published_date,
            "modified_date": cve_modified_date,
            "cvss_base_score": cvss_base_score,
            "cvss_severity": cvss_severity,
            "cvssv2_score": cvssv2_score,
            "cvssv3_score": cvssv3_score,
        }

        return all_cve_info

    def update_cve(self, current_dlc_cve: CVELCM, updated_cve: dict) -> None:
        """Determine if the last modified date from the latest info is newer than the existing info and update.

        Args:
            current_dlc_cve (dict): Dictionary from the current DLM CVE DB.
            updated_cve (dict): Dictionary from the latest software pull for CVE.
        """

        try:
            current_dlc_cve.description = (
                f"{updated_cve['description'][0:251]}..."
                if len(updated_cve["description"]) > 255
                else updated_cve["description"]
            )
        except TypeError:
            current_dlc_cve.description = "No Description Provided from NIST DB."
        current_dlc_cve.last_modified_date = f"{updated_cve['modified_date'][0:10]}"
        current_dlc_cve.link = updated_cve["url"]
        current_dlc_cve.cvss = updated_cve["cvss_base_score"]
        current_dlc_cve.severity = updated_cve["cvss_severity"].title()
        current_dlc_cve.cvss_v2 = updated_cve["cvssv2_score"]
        current_dlc_cve.cvss_v3 = updated_cve["cvssv3_score"]
        current_dlc_cve.comments = "ENTRY UPDATED BY NAUTOBOT NIST JOB"

        try:
            current_dlc_cve.validated_save()
            self.logger.info(
                f"Modified CVE.", 
                extra={
                    "object": current_dlc_cve, 
                    "grouping": "CVE Updates"
                }
            )

        except ValidationError as err:
            self.logger.error(
                f"""Unable to update CVE. ERROR: {err}""", 
                extra={
                    "object": current_dlc_cve, 
                    "grouping": "CVE Updates"
                }
            ) 
