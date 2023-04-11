import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class GmailSender:
    def __init__(self, credentials_file):
        with open(credentials_file, 'r') as f:
            self.smtp_username, self.smtp_password, self.to_address = f.read().splitlines()

        self.smtp_server = 'smtp.gmail.com'
        self.smtp_port = 587
    
    def send_email(self, subject, body):
        # create a message object
        msg = MIMEMultipart()
        msg['From'] = self.smtp_username
        msg['To'] = self.to_address
        msg['Subject'] = subject

        # add some text to the message
        text = body
        msg.attach(MIMEText(text))

        # send the message
        with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
            server.starttls()
            server.login(self.smtp_username, self.smtp_password)
            server.sendmail(self.smtp_username, self.to_address, msg.as_string())

        print('Email sent!')
        
# sender = GmailSender('env.txt')
# sender.send_email('Test email from Python', 'Hello, this is a test email from Python.')
