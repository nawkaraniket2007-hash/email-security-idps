from __future__ import annotations

import os
import tempfile

from flask import Flask, jsonify, request, render_template, send_file
from flask_cors import CORS

from backend.app import analyze_email
from backend.modules.report_generator import generate_report
from backend.modules.actions import quarantine_email
from backend.modules.database import save_analysis
from backend.modules.database import (
    save_analysis,
    get_analysis_history,
    get_analysis,
)

app = Flask(__name__)
CORS(app)

app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "MailSentinel API",
    })


@app.post("/api/analyze")
def analyze():
    # --------------------------------------------------------
    # Validate uploaded file
    # --------------------------------------------------------

    if "email" not in request.files:
        return jsonify({
            "status": "error",
            "error": "No email file provided. Use form field 'email'.",
        }), 400

    uploaded_file = request.files["email"]

    if not uploaded_file.filename:
        return jsonify({
            "status": "error",
            "error": "Empty filename.",
        }), 400

    filename = os.path.basename(uploaded_file.filename)

    if not filename.lower().endswith(".eml"):
        return jsonify({
            "status": "error",
            "error": "Only .eml files are supported.",
        }), 400

    # --------------------------------------------------------
    # Save uploaded email temporarily
    # --------------------------------------------------------

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            suffix=".eml",
            delete=False,
        ) as temp_file:
            uploaded_file.save(temp_file)
            temp_path = temp_file.name

        # ----------------------------------------------------
        # Run complete MailSentinel analysis
        # ----------------------------------------------------

        result = analyze_email(temp_path)

        # Keep original uploaded filename.
        result["email"]["file"] = filename

                # ----------------------------------------------------
        # Automatic quarantine
        # ----------------------------------------------------

        risk = result.get("risk", {})

        classification = risk.get(
            "classification",
            "unknown",
        )

        recommended_action = risk.get(
            "recommended_action",
            "allow",
        )

        if (
            classification == "phishing"
            and recommended_action == "quarantine"
        ):
            quarantine_result = quarantine_email(
                source_path=temp_path,
                original_filename=filename,
                reason="MailSentinel risk engine classified the email as phishing.",
                risk_score=risk.get("score", 0),
            )

            result["quarantine"] = quarantine_result

        else:
            result["quarantine"] = {
                "status": "not_quarantined",
                "reason": (
                    f"Automatic quarantine not required. "
                    f"Classification: {classification}."
                ),
            }

        # ----------------------------------------------------
        # Remove raw attachment bytes before database/API serialization
        # ----------------------------------------------------

        attachments = (
            result
            .get("parser", {})
            .get("attachments", {})
            .get("items", [])
        )

        if isinstance(attachments, list):
            for attachment in attachments:
                if isinstance(attachment, dict):
                    attachment.pop("_content", None)

        # ----------------------------------------------------
        # Save completed analysis to database
        # ----------------------------------------------------

        analysis_id = save_analysis(result)

        result["analysis_id"] = analysis_id

        # ----------------------------------------------------
        # Return analysis result
        # ----------------------------------------------------

        return jsonify(result)

    except Exception as exc:
        return jsonify({
            "status": "error",
            "error": str(exc),
        }), 500

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


@app.get("/api/history")
def history():
    """
    Return recent MailSentinel analysis history.
    """

    try:
        limit = request.args.get(
            "limit",
            default=50,
            type=int,
        )

        records = get_analysis_history(limit)

        # Do not expose internal filesystem paths
        # to the frontend.
        for record in records:
            record.pop(
                "quarantine_path",
                None,
            )

        return jsonify({
            "status": "success",
            "count": len(records),
            "records": records,
        })

    except Exception as exc:
        return jsonify({
            "status": "error",
            "error": str(exc),
        }), 500

@app.get("/api/history/<int:analysis_id>")
def history_detail(analysis_id: int):
    """
    Return the complete historical analysis for one ID.
    """

    analysis = get_analysis(analysis_id)

    if analysis is None:
        return jsonify({
            "status": "error",
            "error": "Analysis record not found.",
        }), 404

    return jsonify({
        "status": "success",
        "analysis": analysis,
    })

@app.post("/api/report")
def report():
    # --------------------------------------------------------
    # Receive completed analysis JSON
    # --------------------------------------------------------

    analysis = request.get_json(silent=True)

    if not isinstance(analysis, dict):
        return jsonify({
            "status": "error",
            "error": "Invalid or missing JSON analysis data.",
        }), 400

    # --------------------------------------------------------
    # Generate PDF report
    # --------------------------------------------------------

    try:
        with tempfile.NamedTemporaryFile(
            suffix=".pdf",
            delete=False,
        ) as temp_file:
            temp_path = temp_file.name

        generate_report(
            analysis,
            temp_path,
        )

        return send_file(
            temp_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name="mailsentinel-security-report.pdf",
        )

    except Exception as exc:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

        return jsonify({
            "status": "error",
            "error": str(exc),
        }), 500


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
    )
