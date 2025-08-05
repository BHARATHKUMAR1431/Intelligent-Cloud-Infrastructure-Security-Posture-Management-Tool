# 🛡️ Intelligent Cloud Infrastructure Security Posture Management Tool (CSPM)

This project is a lightweight **Cloud Security Posture Management (CSPM)** tool developed in Python. It focuses on identifying **public access misconfigurations** in **Google Cloud Storage (GCS) buckets**, helping ensure your cloud infrastructure remains secure.

---

## 🔍 Features

- Scans all GCS buckets in a specified GCP project.
- Detects public access (`allUsers` or `allAuthenticatedUsers`) via IAM bindings.
- Provides a clean and readable security report.
- Handles exceptions like missing credentials and insufficient permissions.

---

## 📦 Requirements

- Python 3.6+
- Google Cloud SDK (for authentication)
- Python packages:
  - `google-cloud-storage`
  - `google-api-core`
  - `google-auth`

Install the dependencies using:

```bash
pip install google-cloud-storage google-api-core google-auth
```

---

## 🔐 Authentication

This tool uses **Application Default Credentials (ADC)**. You can set this up with the following command:

```bash
gcloud auth application-default login
```

Make sure your Google Cloud account has the required IAM permissions (like `Storage Admin` or `Viewer` roles).

---

## ⚙️ Configuration

Before running the tool, update the `GCP_PROJECT_ID` in the `cspm.py` file:

```python
GCP_PROJECT_ID = "your-gcp-project-id"
```

Replace `"your-gcp-project-id"` with your actual Google Cloud project ID.

---

## 🚀 Usage

To run the scan:

```bash
python cspm.py
```

Example output:

```
Starting Google Cloud Security Posture Management (CSPM) scan...
Collecting GCS bucket information for project 'your-project-id'...
Analyzing GCS buckets for public access...
Generating report...
============================================================
           GCP SECURITY REPORT - PUBLIC BUCKETS
============================================================
Total issues found: 1

Bucket: public-bucket-123
  Issue: Public access granted to 'allUsers' with role 'roles/storage.objectViewer'.
------------------------------------------------------------
CSPM scan complete.
```

---

## 📁 Project Structure

```
cspm.py        # Main Python script
README.md      # Documentation file
```

---

## 👨‍💻 Author

Developed by [BHARATHKUMAR1431](https://github.com/BHARATHKUMAR1431)

---

## 📝 License

This project is licensed under the MIT License.
