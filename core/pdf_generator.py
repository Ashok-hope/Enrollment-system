import io
import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

def generate_enrollment_certificate_pdf(
    student_name: str,
    student_identity_hash: str,
    course_code: str,
    course_title: str,
    instructor_name: str,
    block_index: int,
    block_hash: str,
    merkle_root: str,
    tx_id: str,
    student_signature: str,
    admin_signature: str,
    timestamp: str
) -> bytes:
    """
    Generate an official, verifiable Cryptographic Enrollment Certificate PDF.
    Contains complete mathematical proof of inclusion in the immutable blockchain ledger.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    header_style = ParagraphStyle(
        'CertHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        alignment=1 # Center
    )
    
    subtitle_style = ParagraphStyle(
        'CertSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#0284c7'),
        alignment=1
    )
    
    section_title_style = ParagraphStyle(
        'CertSection',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#1e293b')
    )
    
    normal_style = ParagraphStyle(
        'CertNormal',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )
    
    mono_style = ParagraphStyle(
        'CertMono',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor('#0f172a')
    )
    
    badge_style = ParagraphStyle(
        'CertBadge',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#15803d'),
        alignment=1
    )

    story = []

    # Title & Branding
    story.append(Paragraph("ACADEMIC ENROLLMENT CERTIFICATE", header_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph("ZERO-TRUST CRYPTOGRAPHIC BLOCKCHAIN LEDGER AUTHORITY", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=15))

    # Statement of Enrollment
    cert_text = (
        f"This document certifies that <b>{student_name}</b> has completed verified cryptographic course registration "
        f"and has been sealed into the immutable blockchain ledger. This enrollment was signed using "
        f"asymmetric ECDSA digital signatures and authenticated via Merkle Tree inclusion."
    )
    story.append(Paragraph(cert_text, normal_style))
    story.append(Spacer(1, 15))

    # Course & Student Information Table
    course_data = [
        [Paragraph("<b>Course Code:</b>", normal_style), Paragraph(course_code, normal_style)],
        [Paragraph("<b>Course Title:</b>", normal_style), Paragraph(course_title, normal_style)],
        [Paragraph("<b>Instructor:</b>", normal_style), Paragraph(instructor_name, normal_style)],
        [Paragraph("<b>Enrollee Name:</b>", normal_style), Paragraph(student_name, normal_style)],
        [Paragraph("<b>Cryptographic ID:</b>", normal_style), Paragraph(student_identity_hash, mono_style)],
        [Paragraph("<b>Enrollment Timestamp:</b>", normal_style), Paragraph(timestamp, normal_style)]
    ]
    
    t1 = Table(course_data, colWidths=[1.8 * inch, 5.2 * inch])
    t1.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t1)
    story.append(Spacer(1, 15))

    # Blockchain Cryptographic Proofs Section
    story.append(Paragraph("<b>CRYPTOGRAPHIC PROOF & LEDGER PLACEMENT</b>", section_title_style))
    story.append(Spacer(1, 6))

    crypto_data = [
        [Paragraph("<b>Blockchain Block Index:</b>", normal_style), Paragraph(f"Block #{block_index}", normal_style)],
        [Paragraph("<b>Block Header Hash:</b>", normal_style), Paragraph(block_hash, mono_style)],
        [Paragraph("<b>Merkle Tree Root:</b>", normal_style), Paragraph(merkle_root, mono_style)],
        [Paragraph("<b>Transaction ID (SHA-256):</b>", normal_style), Paragraph(tx_id, mono_style)],
        [Paragraph("<b>Student Digital Signature:</b>", normal_style), Paragraph(student_signature[:64] + "...<br/>" + student_signature[64:], mono_style)],
        [Paragraph("<b>Instructor Capability Signature:</b>", normal_style), Paragraph(admin_signature[:64] + "...<br/>" + admin_signature[64:], mono_style)],
        [Paragraph("<b>Inclusion Status:</b>", normal_style), Paragraph("<b>VERIFIED & SEALED IN MERKLE TREE</b>", badge_style)]
    ]

    t2 = Table(crypto_data, colWidths=[1.8 * inch, 5.2 * inch])
    t2.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f5f9')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#94a3b8')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t2)
    story.append(Spacer(1, 20))

    # Verification Notice Footer
    verification_notice = (
        "<b>MATHEMATICAL AUDIT GUARANTEE:</b> This enrollment cannot be forged, repudiated, or altered by any "
        "database administrator or developer. Any post-facto modification to this transaction in storage "
        "invalidates the student's ECDSA signature and breaks the cryptographic Merkle root."
    )
    story.append(Paragraph(verification_notice, normal_style))
    story.append(Spacer(1, 15))

    # Sign-off box
    signoff_data = [
        [Paragraph("<b>Issued by:</b> Zero-Trust Enrollment Engine", normal_style), Paragraph(f"<b>Verification Date:</b> {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", normal_style)]
    ]
    t3 = Table(signoff_data, colWidths=[3.5 * inch, 3.5 * inch])
    t3.setStyle(TableStyle([
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t3)

    doc.build(story)
    return buffer.getvalue()


def generate_course_roster_pdf(
    course_code: str,
    course_title: str,
    instructor_name: str,
    instructor_email: str,
    legitimate_students: list,
    tampered_quarantined: list,
    generated_at: str
) -> bytes:
    """
    Generate an official, cryptographically audited Course Enrollment Roster PDF for instructors.
    Guarantees that ONLY mathematically legitimate students are included, and any
    tampered, injected, or forged enrollments are quarantined and flagged.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    header_style = ParagraphStyle(
        'RosterHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#0f172a'),
        alignment=1
    )

    subtitle_style = ParagraphStyle(
        'RosterSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor('#0284c7'),
        alignment=1
    )

    section_title_style = ParagraphStyle(
        'RosterSection',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#1e293b')
    )

    normal_style = ParagraphStyle(
        'RosterNormal',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor('#334155')
    )

    mono_style = ParagraphStyle(
        'RosterMono',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7,
        leading=9,
        textColor=colors.HexColor('#0f172a')
    )

    badge_verified = ParagraphStyle(
        'RosterBadgeVer',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#15803d')
    )

    badge_tampered = ParagraphStyle(
        'RosterBadgeTam',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#b91c1c')
    )

    story = []

    # Title & Branding
    story.append(Paragraph("OFFICIAL VERIFIED COURSE ENROLLMENT ROSTER", header_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph("CRYPTOGRAPHICALLY AUDITED & FILTERED IMMUTABLE LEDGER RECORDS", subtitle_style))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=12))

    # Course Metadata Summary Box
    summary_data = [
        [Paragraph("<b>Course Code:</b>", normal_style), Paragraph(course_code, normal_style),
         Paragraph("<b>Legitimate Students:</b>", normal_style), Paragraph(f"<b>{len(legitimate_students)} Verified</b>", badge_verified)],
        [Paragraph("<b>Course Title:</b>", normal_style), Paragraph(course_title, normal_style),
         Paragraph("<b>Quarantined / Excluded:</b>", normal_style), Paragraph(f"<b>{len(tampered_quarantined)} Blocked</b>", badge_tampered if tampered_quarantined else normal_style)],
        [Paragraph("<b>Instructor:</b>", normal_style), Paragraph(f"{instructor_name} ({instructor_email})", normal_style),
         Paragraph("<b>Cryptographic Audit:</b>", normal_style), Paragraph("<b>100% Signature & Merkle Proofed</b>", badge_verified)],
        [Paragraph("<b>Roster Generated:</b>", normal_style), Paragraph(generated_at, normal_style),
         Paragraph("<b>Audit Status:</b>", normal_style), Paragraph("ACTIVE INTEGRITY SHIELD", badge_verified)]
    ]

    t_summary = Table(summary_data, colWidths=[1.3 * inch, 2.7 * inch, 1.4 * inch, 1.8 * inch])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 14))

    # Security Alert Box if Tampered Data was detected and excluded
    if tampered_quarantined:
        story.append(Paragraph("⚠️ <b>TAMPERED & INJECTED ATTEMPTS DETECTED (QUARANTINED & EXCLUDED)</b>", section_title_style))
        story.append(Spacer(1, 4))
        alert_desc = (
            "The Zero-Trust verification engine intercepted fraudulent, tampered, or forged student enrollment attempts. "
            "Because digital signatures or hash roots failed validation, <b>these entries have been quarantined and permanently excluded from this legitimate roster:</b>"
        )
        story.append(Paragraph(alert_desc, normal_style))
        story.append(Spacer(1, 6))

        t_tampered_rows = [
            [Paragraph("<b>Block #</b>", normal_style),
             Paragraph("<b>Transaction ID / Attempted ID</b>", normal_style),
             Paragraph("<b>Detection Vector / Reason Blocked</b>", normal_style)]
        ]
        for t in tampered_quarantined:
            t_tampered_rows.append([
                Paragraph(f"Block #{t.get('block_index', '?')}", normal_style),
                Paragraph(t.get('tx_id', t.get('student_name', 'Unknown')), mono_style),
                Paragraph(t.get('reason', 'Signature Forgery / Data Mismatch'), badge_tampered)
            ])

        t_tamper_table = Table(t_tampered_rows, colWidths=[1.0 * inch, 2.5 * inch, 3.7 * inch])
        t_tamper_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#fee2e2')),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fff1f2')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#f87171')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#fca5a5')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_tamper_table)
        story.append(Spacer(1, 14))

    # Legitimate Enrolled Students Table
    story.append(Paragraph("<b>LEGITIMATE ENROLLED STUDENTS (CRYPTOGRAPHICALLY VERIFIED)</b>", section_title_style))
    story.append(Spacer(1, 6))

    if not legitimate_students:
        empty_box = [
            [Paragraph("<i>No confirmed, mathematically verified student enrollments found for this course.</i>", normal_style)]
        ]
        t_empty = Table(empty_box, colWidths=[7.2 * inch])
        t_empty.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(t_empty)
    else:
        table_rows = [
            [
                Paragraph("<b>#</b>", normal_style),
                Paragraph("<b>Student Name & Email</b>", normal_style),
                Paragraph("<b>Pseudonym Identity Hash</b>", normal_style),
                Paragraph("<b>Block</b>", normal_style),
                Paragraph("<b>Tx ID (SHA-256)</b>", normal_style),
                Paragraph("<b>Audit Status</b>", normal_style)
            ]
        ]

        for idx, s in enumerate(legitimate_students, 1):
            id_hash_display = s.get('student_identity_hash', '')
            if len(id_hash_display) > 20:
                id_hash_display = id_hash_display[:10] + "..." + id_hash_display[-8:]
            
            tx_display = s.get('tx_id', '')
            if len(tx_display) > 16:
                tx_display = tx_display[:8] + "..." + tx_display[-6:]

            table_rows.append([
                Paragraph(str(idx), normal_style),
                Paragraph(f"<b>{s.get('student_name', 'Student')}</b><br/><font color='#64748b'>{s.get('student_email', '')}</font>", normal_style),
                Paragraph(id_hash_display, mono_style),
                Paragraph(f"#{s.get('block_index', 1)}", normal_style),
                Paragraph(tx_display, mono_style),
                Paragraph("✓ VERIFIED", badge_verified)
            ])

        t_students = Table(table_rows, colWidths=[0.35 * inch, 2.15 * inch, 1.8 * inch, 0.65 * inch, 1.25 * inch, 1.0 * inch])
        t_students.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e2e8f0')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#94a3b8')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')])
        ]))
        story.append(t_students)

    story.append(Spacer(1, 16))

    # Mathematical Verification Guarantee & Signoff
    guarantee_text = (
        "<b>MATHEMATICAL ENROLLMENT GUARANTEE:</b> Every student in this roster was verified through end-to-end "
        "cryptographic proofs: (1) Valid Instructor Invite Capability Signature, (2) Authentic Student ECDSA P-256 "
        "Signature, (3) Merkle Tree Inclusion Proof, and (4) Unbroken SHA-256 Hash Chaining. "
        "Any developer modification, injection, or backdoor tampering invalidates verification and is automatically excluded."
    )
    story.append(Paragraph(guarantee_text, normal_style))
    story.append(Spacer(1, 10))

    signoff_data = [
        [Paragraph(f"<b>Certified Instructor:</b> {instructor_name}", normal_style),
         Paragraph(f"<b>Ledger Engine Seal:</b> SHA-256 Verified at {generated_at}", normal_style)]
    ]
    t_signoff = Table(signoff_data, colWidths=[3.6 * inch, 3.6 * inch])
    t_signoff.setStyle(TableStyle([
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(t_signoff)

    doc.build(story)
    return buffer.getvalue()

