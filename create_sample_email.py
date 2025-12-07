# create_sample_email.py
sample_eml = """From: "PayPal Security" <security@fake-paypal.com>
To: user@example.com
Subject: Urgent: verify your account now
Reply-To: "PayPal Support" <support@fake-paypal-secure.com>
Message-ID: <1234567890@example.com>
Received-SPF: fail (domain of fake-paypal.com does not designate 1.2.3.4 as permitted sender)
Authentication-Results: mx.example.com;
    spf=fail (sender IP is 1.2.3.4) smtp.mailfrom=fake-paypal.com;
    dkim=fail header.i=@fake-paypal.com;
    dmarc=fail action=reject header.from=fake-paypal.com;
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 8bit
MIME-Version: 1.0

Dear customer,

We noticed suspicious activity on your account.
To protect your account, please verify your account information immediately.

Click the link below to verify your account:

https://secure-paypal-login-verify.example.com/login

If you do not verify your account within 24 hours, your account will be suspended.

Best regards,
PayPal Security Team
"""

with open("sample_email.eml", "w", encoding="utf-8") as f:
    f.write(sample_eml)

print("Файл sample_email.eml создан.")
