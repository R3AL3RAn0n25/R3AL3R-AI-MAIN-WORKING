if __name__ == '__main__':
    app.run(
        host='0.0.0.0', 
        port=443, 
        ssl_context=('/home/ubuntu/r3aler-ai/r3al3rai.com_ssl_certificate.cer', '/home/ubuntu/r3aler-ai/r3aler_ai_private.key'),
        debug=False
    )