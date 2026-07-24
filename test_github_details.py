from pprint import pprint

from database.database import get_github_advisory_details

# Replace with a real GHSA ID from your database
GHSA_ID = "GHSA-g59m-gf8j-gjf5"

advisory = get_github_advisory_details(GHSA_ID)

if advisory is None:
    print("No advisory found.")
else:
    pprint(advisory)