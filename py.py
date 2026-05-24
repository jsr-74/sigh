from flask import Flask, request, jsonify, send_file
from waitress import serve
from pyhanko.sign import signers
from pyhanko.sign.signers import PdfSigner, PdfSignatureMetadata
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import os
import base64
import datetime

# =========================================================
# FLASK APP
# =========================================================

app = Flask(__name__)

# =========================================================
# CONFIGURATION
# =========================================================

SIGNED_FOLDER = "signed_pdfs"

PRIVATE_KEY = "private_key.pem"
CERT_FILE = "certificate.pem"

os.makedirs(SIGNED_FOLDER, exist_ok=True)

# =========================================================
# GET API
# GENERATE CERTIFICATE + PRIVATE KEY
# =========================================================

@app.route("/generate-certificate", methods=["GET"])
def generate_certificate():

    try:

        # =================================================
        # GENERATE PRIVATE KEY
        # =================================================

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Save Private Key
        with open(PRIVATE_KEY, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        # =================================================
        # CERTIFICATE DETAILS
        # =================================================

        subject = issuer = x509.Name([
            x509.NameAttribute(
                NameOID.COUNTRY_NAME,
                u"IN"
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                u"Lakshmi Reddy"
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                u"Digital Signature"
            ),
        ])

        # =================================================
        # CREATE CERTIFICATE
        # =================================================

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(
                x509.random_serial_number()
            )
            .not_valid_before(
                datetime.datetime.utcnow()
            )
            .not_valid_after(
                datetime.datetime.utcnow() +
                datetime.timedelta(days=365)
            )
            .sign(
                key,
                hashes.SHA256(),
                default_backend()
            )
        )

        # Save Certificate
        with open(CERT_FILE, "wb") as f:
            f.write(
                cert.public_bytes(
                    serialization.Encoding.PEM
                )
            )

        return jsonify({
            "status": "success",
            "message": "Certificate generated successfully",
            "certificate_file": CERT_FILE,
            "private_key_file": PRIVATE_KEY,
            "signed_folder": SIGNED_FOLDER
        })

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# =========================================================
# OPTIONAL DOWNLOAD CERTIFICATE API
# =========================================================

@app.route("/download-certificate", methods=["GET"])
def download_certificate():

    if not os.path.exists(CERT_FILE):

        return jsonify({
            "status": "error",
            "message": "Certificate not found"
        }), 404

    return send_file(
        CERT_FILE,
        as_attachment=True
    )

# =========================================================
# DIGITAL SIGN FUNCTION
# =========================================================

def sign_pdf(input_pdf_path, output_pdf_path):

    with open(input_pdf_path, "rb") as inf, \
         open(output_pdf_path, "wb") as outf:

        writer = IncrementalPdfFileWriter(inf)

        signer = signers.SimpleSigner.load(
            key_file=PRIVATE_KEY,
            cert_file=CERT_FILE
        )

        signature_meta = PdfSignatureMetadata(
            field_name="Signature1",
            reason="Approved",
            location="India"
        )

        sig_field = SigFieldSpec(
            sig_field_name="Signature1",
            box=(50, 50, 220, 100)
        )

        pdf_signer = PdfSigner(
            signature_meta=signature_meta,
            signer=signer,
            new_field_spec=sig_field
        )

        pdf_signer.sign_pdf(
            writer,
            output=outf
        )

# =========================================================
# POST API
# SIGN PDF
# =========================================================

@app.route("/sign-pdf", methods=["POST"])
def sign_pdf_api():

    try:

        # =================================================
        # CHECK CERTIFICATE EXISTS
        # =================================================

        if not os.path.exists(PRIVATE_KEY) or \
           not os.path.exists(CERT_FILE):

            return jsonify({
                "status": "error",
                "message": "Generate certificate first using GET API"
            }), 400

        # =================================================
        # GET JSON
        # =================================================

        data = request.get_json()

        if not data:

            return jsonify({
                "status": "error",
                "message": "No JSON received"
            }), 400

        pdf_base64 = data.get("pdf_data")

        if not pdf_base64:

            return jsonify({
                "status": "error",
                "message": "pdf_data missing"
            }), 400

        # =================================================
        # REMOVE PREFIX IF EXISTS
        # =================================================

        if "," in pdf_base64:
            pdf_base64 = pdf_base64.split(",")[1]

        # =================================================
        # BASE64 DECODE
        # =================================================

        try:

            pdf_bytes = base64.b64decode(
                pdf_base64
            )

        except Exception as e:

            return jsonify({
                "status": "error",
                "message": f"Base64 decode failed: {str(e)}"
            }), 400

        # =================================================
        # VALIDATE PDF
        # =================================================

        if not pdf_bytes.startswith(b'%PDF'):

            return jsonify({
                "status": "error",
                "message": "Invalid PDF received"
            }), 400

        # =================================================
        # FILE NAMES
        # =================================================

        timestamp = datetime.datetime.now().strftime(
            "%Y%m%d%H%M%S"
        )

        input_pdf_path = os.path.join(
            SIGNED_FOLDER,
            f"input_{timestamp}.pdf"
        )

        signed_pdf_path = os.path.join(
            SIGNED_FOLDER,
            f"signed_{timestamp}.pdf"
        )

        # =================================================
        # SAVE INPUT PDF
        # =================================================

        with open(input_pdf_path, "wb") as f:
            f.write(pdf_bytes)

        # =================================================
        # SIGN PDF
        # =================================================

        sign_pdf(
            input_pdf_path,
            signed_pdf_path
        )

        # =================================================
        # CONVERT SIGNED PDF TO BASE64
        # =================================================

        with open(signed_pdf_path, "rb") as f:

            signed_pdf_base64 = base64.b64encode(
                f.read()
            ).decode("utf-8")

        # =================================================
        # RESPONSE
        # =================================================

        return jsonify({
            "status": "success",
            "message": "PDF signed successfully",
            "signed_file": signed_pdf_path,
            "signed_pdf_base64": signed_pdf_base64
        })

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    serve(
        app,
        host="0.0.0.0",
        port=5000
    )
