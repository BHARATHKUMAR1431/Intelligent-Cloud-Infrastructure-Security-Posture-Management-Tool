from google.cloud import storage
from google.api_core import exceptions
import google.auth


GCP_PROJECT_ID = "clean-outcome-468116-r2"



def get_gcs_buckets():
    """
    Retrieves a list of all GCS buckets in the configured project.

    Returns:
        list: A list of GCS bucket objects.
    """
    try:
        storage_client = storage.Client(project=GCP_PROJECT_ID)
        buckets = storage_client.list_buckets()
        return list(buckets)
    except google.auth.exceptions.DefaultCredentialsError:
        print("Google Cloud credentials not found.")
        print("Please run 'gcloud auth application-default login' to configure your credentials.")
        return []
    except Exception as e:
        print(f"An error occurred while fetching GCS buckets: {e}")
        return []




def check_public_gcs_buckets(buckets):
    """
    Checks a list of GCS buckets for public access.

    Args:
        buckets (list): A list of GCS bucket objects.

    Returns:
        list: A list of findings, where each finding is a dictionary
              containing the bucket name and the issue.
    """
    findings = []
    public_principals = {"allUsers", "allAuthenticatedUsers"}

    for bucket in buckets:
        try:
           
            policy = bucket.get_iam_policy(requested_policy_version=3)

           
            for binding in policy.bindings:
                
                if public_principals.intersection(binding["members"]):
                    findings.append(
                        {
                            "bucket_name": bucket.name,
                            "issue": f"Public access granted to '{', '.join(binding['members'])}' with role '{binding['role']}'.",
                        }
                    )
                    
                    break

        except exceptions.Forbidden as e:
            print(f"Permission denied for bucket {bucket.name}. Skipping. Error: {e}")
        except Exception as e:
            print(f"An error occurred while checking bucket {bucket.name}: {e}")

    return findings




def generate_report(findings):
    """
    Generates a simple report of the security findings.

    Args:
        findings (list): A list of security findings.
    """
    if not findings:
        print("No public GCS buckets found. Your configuration appears secure.")
        return

    print("=" * 60)
    print("           GCP SECURITY REPORT - PUBLIC BUCKETS")
    print("=" * 60)
    print(f"Total issues found: {len(findings)}\n")

    for finding in findings:
        print(f"Bucket: {finding['bucket_name']}")
        print(f"  Issue: {finding['issue']}")
        print("-" * 60)


def main():
    """
    Main function to run the CSPM tool for Google Cloud.
    """
    if GCP_PROJECT_ID == "your-gcp-project-id":
        print("Please configure your GCP_PROJECT_ID in the script before running.")
        return
        
    print("Starting Google Cloud Security Posture Management (CSPM) scan...")

   
    print(f"Collecting GCS bucket information for project '{GCP_PROJECT_ID}'...")
    gcs_buckets = get_gcs_buckets()

    if not gcs_buckets:
        print("No GCS buckets found to analyze or an error occurred.")
        return

    
    print("Analyzing GCS buckets for public access...")
    public_bucket_findings = check_public_gcs_buckets(gcs_buckets)

   
    print("Generating report...")
    generate_report(public_bucket_findings)

    print("CSPM scan complete.")


if __name__ == "__main__":
    main()
