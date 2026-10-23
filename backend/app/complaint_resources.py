"""Maintained directory of official cyber incident reporting destinations."""

VERIFIED_ON = "2026-10-23"

COMPLAINT_RESOURCES = [
    {
        "id": "national-cybercrime-portal",
        "name": "National Cyber Crime Reporting Portal",
        "url": "https://cybercrime.gov.in/",
        "jurisdiction": "India · Government of India / I4C",
        "purpose": "Report cybercrime, including online financial fraud, social media abuse, hacking, and crimes against women or children. For urgent financial cyber fraud, the official portal also identifies helpline 1930.",
        "source_urls": [
            "https://cybercrime.gov.in/",
            "https://cybercrime.gov.in/Webform/FAQ.aspx",
        ],
        "verified_on": VERIFIED_ON,
        "official": True,
    },
    {
        "id": "chakshu",
        "name": "Chakshu · Sanchar Saathi",
        "url": "https://sancharsaathi.gov.in/sfc/",
        "jurisdiction": "India · Department of Telecommunications",
        "purpose": "Report suspected fraudulent communication received by call, SMS, or WhatsApp. If money was lost or a cybercrime occurred, use the National Cyber Crime Reporting Portal or 1930 as well.",
        "source_urls": [
            "https://sancharsaathi.gov.in/sfc/",
            "https://www.sancharsaathi.gov.in/SancharSaathiDocuments/ImportantDocuments/Press%20Release-DoT%20takes%20action%20against%20Electricity%20KYC%20Update%20Scam.pdf",
        ],
        "verified_on": VERIFIED_ON,
        "official": True,
    },
    {
        "id": "rbi-sachet",
        "name": "Sachet · RBI",
        "url": "https://sachet.rbi.org.in/",
        "jurisdiction": "India · Reserve Bank of India and other regulators",
        "purpose": "Share information or raise a complaint about unauthorized deposit collection or schemes that have defaulted on repayment. For cyber-enabled money loss, also report to the cybercrime portal and your bank through its official channel.",
        "source_urls": [
            "https://sachet.rbi.org.in/",
            "https://www.rbi.org.in/Scripts/PublicationsView.aspx?id=20313",
        ],
        "verified_on": VERIFIED_ON,
        "official": True,
    },
]

SAFE_FALLBACK = (
    "If a specialized resource is unavailable, start at https://cybercrime.gov.in/ or contact your local police. "
    "For money already transferred, contact your bank through its official app or website and use the cybercrime helpline 1930."
)
