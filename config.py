import os

class Config:
    # Flask Secret Key
    SECRET_KEY = os.environ.get('SECRET_KEY', 'whatsapp-bulk-bot-2024!@#$%secret_key_12345ABCDEFGHIJK')
    
    # Google Sheets Configuration from Environment Variables
    GOOGLE_SHEETS_CREDENTIALS = {
        "type": "service_account",
        "project_id": os.environ.get('GOOGLE_PROJECT_ID', 'whatsappbot-478316'),
        "private_key_id": os.environ.get('GOOGLE_PRIVATE_KEY_ID', 'dbe15e026c07ac87162b6f51e29dc65c04b38aaf'),
        "private_key": os.environ.get('GOOGLE_PRIVATE_KEY', '-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDkCHyO5yXukIlZ\n2ZKner+wajP5nbaRTZB36I+849yjltZ2KnxHoHCx20ZAMBmZJh2e+Rwsq4EYO6MD\ng/SYyVmUKk+gnO9CSUfrZZnCdmbRkRo45ukHCsKlAdJUE5i8/rmQoxiCycpN8+wU\nyVkYdJdxNetcM/IS3X/owiWg/NcG/duRBdLGxua8hUA2fSyycdYiZPge6pkeiKc/\nIDXnos0pika+UmMV8N2FY5cEHOceaILDY4oFYPlNpuXpk/X8rUQLtYwFmw8A1ZfY\ncbDrj4J+SlbjJ2xR1XgNhSy4+MdXe/JRlzDmcN6+K7s/7aVUXQyXAQ0usVCNI27N\n+nkGBoCtAgMBAAECggEAHMiBcxxJf8UYwTxNtFGHKVfOewnlmzkE16MwTtxy45H3\nkhonbncZon7rbXtkz8hYNtJ6NEfrAfRieDV2G2RW/Up18JppN58TspU0L6/4UdLp\n/MK7fpsPb0/n4kWdovAthiHqxx980hLMUDdgxU3Pi90Nef7zOwm1yoXZxWoEzlSM\ncbpNjURCNe/v+yQGEcRcrm4pmjufk1MYEjFgR2PM2TRT0oNK1/OfdWs3EpbMSznC\nirCL+xzikpQ2jblPKZfyJKcj/SZ5c5SjvQBfbL1y05NuzUwbwrckaGEFYNe5FEvP\n3QkrMdiAB+fL1d0Y7wMDgRq2bxUaN3ikqwwAeUztdQKBgQD0Q4je+a8Fxo7WYAI5\nwjfVv28KAwEQCZsoTxTOarRnvsBwQQcIkm3CeJ72u8ESlUtze9jlHfuv141w6O2T\nNA7HY6LJAXz7ECL4++xjB3T714Z+2nnfmijVMd64wMGNIpMZ7m8QfciphRpVpTfv\nCLmtPFQP98xQ3+b5IIbc3Dt1zwKBgQDu/VA/IMSrXZuzjM6Hb8ZZzCm+cGuUJuMN\n+/nfuPcNxsQxxry7CeimLyZB7CReCmVo2G40ROECtkYrkD/jS2CYj0jf5RuA3gZ\n4o1GeH8DMJfDq0tdZ9sf1byJJCgbdJ8a5WjhVt9L6jDLhZNOSoaWKCdq5TB9GxnG\nTYcPK/z8wwJ/XnW/eHsWNCWVF1IJikyRSxe82SJQRuNwHSZ35VteaMBbqw16qtX1\nnD8JOmFhSM5zXzWFqxTtQBMbn450UXjQPktJqHHq4yxaWe8SezlnA/1VBbl3aAE1\nyTx/5PKl5u539I9AZCBAeU3/4R8DgmzdYSDzYTlyydPMfosVnFOOqwKBgQC4xXZ+\naCpFx2iy5+FhiwSStqtrhmVWNL6FOFRXKR0xNITJazrNbPrHSVrNyvHPF0CSUArc\nNIi23VxdLZQpQBB4ZtWYFXI/oEUB1kuduVmRsMcVS+FHxR0APvK2IRM1LvQ4CjgN\nSGn5uoWhRJPACxSFEWRwW+QiRYqm65fJHhxJmwKBgQCHzuDbkEAEErr7RyfYDoeI\nboTqSevECSOaDKzKZaC4S+YvZ6TELd98+osAuy3+RKdQ8N+0HHvjrimBW495U07S\nM0yePSiiGPAyx08pRQpdUkFMY7Mdj5EjSQnEe2TY9cpCakW1IGfZvqyBQM9Xicmk\n3ZunRbomu2hqdGRCMRi9zg==\n-----END PRIVATE KEY-----\n').replace('\\n', '\n'),
        "client_email": os.environ.get('GOOGLE_CLIENT_EMAIL', 'whatsapp-bot-service@whatsappbot-478316.iam.gserviceaccount.com'),
        "client_id": os.environ.get('GOOGLE_CLIENT_ID', '112647679419855179779'),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": os.environ.get('GOOGLE_CLIENT_X509_CERT_URL', 'https://www.googleapis.com/robot/v1/metadata/x509/whatsapp-bot-service%40whatsappbot-478316.iam.gserviceaccount.com'),
        "universe_domain": "googleapis.com"
    }
    
    MASTER_SHEET_URL = os.environ.get('MASTER_SHEET_URL', 'https://docs.google.com/spreadsheets/d/YOUR_SHEET_ID_HERE/edit')
    
    BOT_SERVERS = [
        'https://bot-1-ztr9.onrender.com',
        'https://bot2-jrbf.onrender.com'
    ]