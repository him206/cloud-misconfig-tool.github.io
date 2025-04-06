import streamlit as st
import boto3
from datetime import datetime

# Streamlit page config
st.set_page_config(page_title="AWS Security Scanner", layout="wide")

# AWS Clients
s3 = boto3.client('s3')
ec2 = boto3.client('ec2')

# Custom CSS for dark mode tweaks
st.markdown("""
    <style>
        .stApp {
            background-color: #111111;
            color: #FFFFFF;
        }
        .stMetric label {
            color: #AAAAAA !important;
        }
    </style>
""", unsafe_allow_html=True)

# ===========================
# S3 Public Bucket Scan
# ===========================

def remediate_public_s3(bucket_name):
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        return True
    except Exception as e:
        st.error(f"❌ Failed to remediate {bucket_name}: {e}")
        return False

def check_public_s3_buckets():
    public_buckets = []
    try:
        buckets = s3.list_buckets()['Buckets']
        for bucket in buckets:
            bucket_name = bucket['Name']
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl['Grants']:
                if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    public_buckets.append(bucket_name)
                    if remediate_public_s3(bucket_name):
                        st.success(f"🔧 Remediation applied to: {bucket_name}")
        return buckets, public_buckets
    except Exception as e:
        st.error(f"⚠️ Error scanning S3: {e}")
        return [], []

# ===========================
# Security Groups (Firewall) Scan
# ===========================

def check_security_groups():
    open_ports = []
    try:
        response = ec2.describe_security_groups()
        for sg in response['SecurityGroups']:
            for permission in sg['IpPermissions']:
                for ip_range in permission.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        port = permission.get('FromPort', 'ALL')
                        open_ports.append((sg['GroupId'], sg['GroupName'], port))
        return open_ports
    except Exception as e:
        st.error(f"⚠️ Error scanning security groups: {e}")
        return []

# ===========================
# UI Layout
# ===========================

st.title("☁️ AWS Security Misconfiguration Dashboard")
st.caption("🔒 Scans for S3 bucket exposure and open firewall ports.")

# Scan buttons
col1, col2 = st.columns(2)

with col1:
    if st.button("🔍 Scan S3 Buckets"):
        buckets, public = check_public_s3_buckets()
        st.metric(label="Total Buckets", value=len(buckets))
        st.metric(label="Public Buckets", value=len(public))
        st.success("✅ S3 Scan Complete")

with col2:
    if st.button("🔍 Scan Security Groups"):
        open_ports = check_security_groups()
        st.metric(label="Open Security Group Rules", value=len(open_ports))
        if open_ports:
            st.warning("🚨 Open ports found:")
            for sg_id, sg_name, port in open_ports:
                st.text(f"Group: {sg_name} | Port: {port}")
        else:
            st.success("✅ No publicly open ports found.")

# Timestamp
st.markdown(f"🕒 Last scanned at: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`")
