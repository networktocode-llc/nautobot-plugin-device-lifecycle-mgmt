# pylint: disable=logging-not-lazy, consider-using-f-string
"""Jobs for the CVE Tracking portion of the Device Lifecycle app."""
from datetime import datetime, date
from os import getenv
from time import sleep

from urllib3.util import Retry
from requests import Session
from requests.adapters import HTTPAdapter
from requests.exceptions import HTTPError

from netutils.lib_mapper import NIST_LIB_MAPPER_REVERSE
from netutils.nist import get_nist_vendor_platform_urls

from django.core.exceptions import ValidationError
from django.db.utils import IntegrityError

from nautobot.dcim.models import Device, InventoryItem
from nautobot.dcim.models.devices import SoftwareVersion
from nautobot.extras.jobs import BooleanVar, Job, StringVar

from nautobot_device_lifecycle_mgmt.models import CVELCM, VulnerabilityLCM

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
    debug = BooleanVar(description="Enable for more verbose logging.")

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
        published_after = published_after if published_after is not None else "1970-01-01"
        cves = CVELCM.objects.filter(published_date__gte=datetime.fromisoformat(published_after))
        count_before = VulnerabilityLCM.objects.count()

        for cve in cves:
            if debug:
                self.logger.info(
                    "Generating vulnerabilities for CVE %s" % cve,
                    extra={"object": cve},
                )
            for software in cve.affected_softwares.all():
                for device in Device.objects.filter(software_version=software):
                    VulnerabilityLCM.objects.get_or_create(cve=cve, software=software, device=device)

                for inventory_item in InventoryItem.objects.filter(software_version=software):
                    VulnerabilityLCM.objects.get_or_create(cve=cve, software=software, inventory_item=inventory_item)

        diff = VulnerabilityLCM.objects.count() - count_before
        self.logger.info("Processed %d CVEs and generated %d Vulnerabilities." % (cves.count(), diff))


class NistCveSyncSoftware(Job):
    """Checks all device SoftwareVersion for NIST recorded vulnerabilities."""

    name = "NIST - Software CVE Search"
    description = "Searches the NIST DBs for CVEs related to SoftwareVersion"
    read_only = False

    class Meta:  # pylint: disable=too-few-public-methods
        """Meta class for the job."""

        commit_default = True
        soft_time_limit = 3600

    def __init__(self):
        """Initializing job with extra options."""
        super().__init__()
        self.nist_api_key = getenv("NAUTOBOT_DLM_NIST_API_KEY")
        self.sleep_timer = 0.75
        self.headers = {"ContentType": "application/json", "apiKey": self.nist_api_key}

        # Set session attributes for retries
        self.session = Session()
        retries = Retry(
            total=3,
            backoff_factor=10,
            status_forcelist=[502, 503, 504],
            allowed_methods={"GET"},
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retries))

    def run(self, *args, **kwargs):
        """Check all software in DLC against NIST database and associate registered CVEs.  Update when necessary."""
        cve_counter = 0

        for software in SoftwareVersion.objects.all():
            manufacturer = software.platform.manufacturer.name.lower()
            platform = software.platform.network_driver.lower()
            version = software.version.replace(" ", "")

            try:
                platform = NIST_LIB_MAPPER_REVERSE[platform]
            except KeyError:
                self.logger.warning(
                    "OS Platform %s is not yet supported; Skipping.", platform,
                    extra={"object": software.platform, "grouping": "CVE Information"},
                )
                continue

            try:
                cpe_software_search_urls = self.create_cpe_software_search_urls(manufacturer, platform, version)
            except TypeError:
                self.logger.error(
                    "There is an issue with the Software Version in Nautobot. Please check the version value.",
                    extra={"grouping": "URL Creation"},
                )
                continue

            self.logger.info(
                "Gathering CVE Information for Software Version: %s", version,
                extra={"object": software.platform, "grouping": "CVE Information"},
            )

            software_cve_info = self.get_cve_info(cpe_software_search_urls, software.id)
            all_software_cve_info = {**software_cve_info["new"], **software_cve_info["existing"]}

            cve_counter += len(software_cve_info["new"])
            self.create_dlc_cves(software_cve_info["new"])

            for software_cve, cve_info in all_software_cve_info.items():
                matching_dlc_cve = CVELCM.objects.get(name=software_cve)
                self.associate_software_to_cve(software.id, matching_dlc_cve.id)
                if str(cve_info["modified_date"][0:10]) != str(matching_dlc_cve.last_modified_date):
                    self.update_cve(matching_dlc_cve, cve_info)
                    continue

            # API Rest Timer
            sleep(6)

        self.logger.info(
            "Performed discovery on all software. Created %s CVE.", cve_counter, extra={"grouping": "CVE Creation"}
        )
        self.session.close()

    def associate_software_to_cve(self, software_id, cve_id):
        """A function to associate software to a CVE."""
        cve = CVELCM.objects.get(id=cve_id)
        software = SoftwareVersion.objects.get(id=software_id)

        try:
            cve.affected_softwares.add(software)

        except IntegrityError as err:
            self.logger.error(
                "Unable to create association between CVE and Software Version.  ERROR: %s", err,
                extra={"object": cve, "grouping": "CVE Association"},
            )

    @staticmethod
    def create_cpe_software_search_urls(vendor: str, platform: str, version: str) -> list:
        """Uses netutils.platform_mapper to construct proper search URLs.

        Args:
            vendor (str): Software Vendor (Examples: Cisco, Juniper, Arista)
            platform (str): Software Platform (Examples: IOS, JunOS, EOS)
            version (str): Software Version

        Returns:
            list: List of URLS that associated CVEs may be found
        """
        cpe_urls = get_nist_vendor_platform_urls(vendor, platform, version)

        return cpe_urls

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

        self.logger.info("Created New CVEs.", extra={"grouping": "CVE Creation"})

    def get_cve_info(self, cpe_software_search_urls: list, software_id=None) -> dict:
        """Search NIST for software and related CVEs."""
        for cpe_software_search_url in cpe_software_search_urls:
            result = self.query_api(cpe_software_search_url)

            all_cve_info = {"new": {}, "existing": {}}
            if result["totalResults"] > 0:
                self.logger.info(
                    "Received %s results.", result["totalResults"],
                    extra={"object": SoftwareVersion.objects.get(id=software_id), "grouping": "CVE Creation"},
                )
                cve_list = [cve["cve"] for cve in result["vulnerabilities"]]
                dlc_cves = [cve.name for cve in CVELCM.objects.all()]

                all_cve_info = self.process_cves(cve_list, dlc_cves, software_id)

        return all_cve_info

    def process_cves(self, cve_list, dlc_cves, software_id):
        """Method to return processed CVE info.

        Args:
            cve_list (list): List of CVE returned from CPE search
            dlc_cves (list): List of all DLM CVE objects
            software_id (object): UUID of the Software being queried

        Returns:
            dict: Dictionary of CVEs in either new or existing categories
        """
        processed_cve_info = {"new": {}, "existing": {}}
        if cve_list:
            for cve in cve_list:
                cve_name = cve["id"]
                if cve_name.startswith("CVE"):
                    if cve_name not in dlc_cves:
                        processed_cve_info["new"].update({cve_name: self.prep_cve_for_dlc(cve)})
                    else:
                        processed_cve_info["existing"].update({cve_name: self.prep_cve_for_dlc(cve)})
            self.logger.info(
                "Prepared %s CVE for creation." % len(processed_cve_info["new"]),
                extra={"object": SoftwareVersion.objects.get(id=software_id), "grouping": "CVE Creation"},
            )

        return processed_cve_info

    def query_api(self, url):
        """Establishes a session for use of retries and backoff.

        Args:
            url (string): The API endpoint getting queried.

        Returns:
            dict: Dictionary of returned results if successful.
        """
        try:
            result = self.session.get(url, headers=self.headers)
            result.raise_for_status()
        except HTTPError as err:
            code = err.response.status_code
            self.logger.error(
                "The NIST Service is currently unavailable. Status Code: %s. Try running the job again later.", code
            )

        return result.json()

    @staticmethod
    def convert_v2_base_score_to_severity(score: float) -> str:
        """Uses V2 Base Score to convert to Severity Value.

        Args:
            score (float): CVSS V2 Base Score

        Returns:
            str: Severity Value ["HIGH", "MEDIUM", "LOW", "UNDEFINED"]
        """
        if 0.0 >= score <= 3.9:
            return "LOW"
        if 4.0 >= score <= 6.9:
            return "MEDIUM"
        if 7.0 >= score <= 10:
            return "HIGH"
        return "UNDEFINED"

    def prep_cve_for_dlc(self, cve_json):  # pylint: disable=too-many-locals
        """Converts CVE info into DLC Model compatibility."""
        cve = cve_json

        # cve_base = cve["vulnerabilities"][0]['cve']
        cve_base = cve
        cve_name = cve_base["id"]
        for desc in cve_base["descriptions"]:
            if desc["lang"] == "en":
                cve_description = desc["value"]
            else:
                cve_description = "No description provided."
        cve_published_date = cve_base.get("published")
        cve_modified_date = cve_base.get("lastModified")
        cve_impact = cve_base["metrics"]

        # Determine URL
        if len(cve_base["references"]) > 0:
            cve_url = cve_base["references"][0].get("url", f"https://www.cvedetails.com/cve/{cve_name}/")
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
            cvss_severity = cve_impact["cvssMetricV2"][0]["baseSeverity"] or self.convert_v2_base_score_to_severity(
                cvss_base_score
            )
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
            self.logger.info("Modified CVE.", extra={"object": current_dlc_cve, "grouping": "CVE Updates"})

        except ValidationError as err:
            self.logger.error(
                "Unable to update CVE. ERROR: %s", err, extra={"object": current_dlc_cve, "grouping": "CVE Updates"}
            )
