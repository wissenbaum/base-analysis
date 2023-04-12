from distutils.log import debug
from fileinput import filename
from datetime import datetime
from flask import *
import pandas as pd
import numpy as np
import re
import os


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

@app.route('/')
def index():
    msg= '<h1>This a home page</h1>'
    return msg
    # return render_template('test.html')

@app.route('/traffic')
def traffic():
    df = pd.read_csv('csv/cleaned_loged.csv', low_memory=False)
    hourly_table = pd.pivot_table(data=df,index=['hour'],values=['byte'],aggfunc={len,np.sum})
    hourly_table.to_csv("csv/hourly_conn_bytes.csv")
    hourly_conn_bytes = pd.read_csv("csv/hourly_conn_bytes.csv",skiprows=3,sep=',',names=['hour','connection','bytes'])
    hourly_conn_bytes.to_csv("csv/hourly_conn_bytes.csv",index=False)

    hours=hourly_conn_bytes.hour.to_list()
    connection=hourly_conn_bytes.connection.to_list()
    bytes=hourly_conn_bytes.bytes.to_list()
    duration=hourly_conn_bytes.connection.to_list()
    return render_template('traffic_conn_byte.html', hours=hours, connection=connection, bytes=bytes, duration=duration)

@app.route('/configure/<filename>')
def configure(filename):
    startTime = datetime.now()
    filepath=os.path.join(app.config['UPLOAD_FOLDER'], filename)
    print(filepath)
    
    df=pd.read_csv(filepath, sep='delimiter', header=None, engine='python')
    # print(df.shape)
    
    df=df[~df[0].str.contains("block")]
    df=df[~df[0].str.contains("rule-20")]
    # print(df.shape)

    log = df.to_string()

    # Define a regular expression to extract relevant fields from the log
    regex = r"^(.*?)\s.(\d{4}:\d{2}:\d{2}-\d{2}:\d{2}:\d{2})\s.*?GSHIELD=(.*?)\s.*?SRC=(.*?)\s.*?DST=(.*?)\s.*?LEN=(.*?)\s.*?PROTO=(.*?)\s.*?SPT=(.*?)\s.*?DPT=(.*?)\s"

    # Create a list to store the extracted information
    data = []

    # Loop through the log and extract the relevant fields using the regular expression
    for line in log.strip().split("\n"):
        match = re.match(regex, line)
        if match:
            index, timestamp, gshield_info, src_ip, dst_ip, byte, protocol, src_port, dst_port = match.groups()
            data.append({
                "timestamp": timestamp,
                "gshield_info": gshield_info,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "byte": byte,
                "protocol": protocol,
                "src_port": src_port,
                "dst_port": dst_port,
            })

    # Convert the list of dictionaries into a Pandas DataFrame
    df = pd.DataFrame(data)
    #split timestamp 
    df[['date','time']]=df['timestamp'].str.split("-",expand = True)
    df[['hour','minute','second']]=df['time'].str.split(":",expand = True)

    # stored cleaning data into .csv file
    df.to_csv("csv/cleaned_loged.csv",index=False)
    
    # Display the resulting DataFrame
    print(df.head())  

    # Total number of rules found/used
    rules=df.gshield_info.nunique()
    
    # count of unique values of src_ip
    src_ip= df.src_ip.nunique()
    
    # count of unique values of dst_ip
    dst_ip= df.dst_ip.nunique()
    
    # count of unique values of src_ports
    src_ports= df.src_port.nunique()
    
    # count of unique values of dst_port
    dst_port= df.dst_port.nunique()

    #pass data to webpage
    df=df.head(20)
    data = df.to_dict('records')
    header = df.columns.tolist()
    msg='File Configured successful!'

    endTime = datetime.now()
    print("startTime: ",startTime)
    print("endTime: ",endTime)
    print("Processing Time:",endTime - startTime)

    return render_template('configure.html', 
                           data=data, header=header, msg=msg, 
                           rules=rules, src_ip=src_ip, dst_ip=dst_ip, 
                           src_ports=src_ports, dst_port=dst_port)

#single file_upload
@app.route('/file_upload', methods=['GET', 'POST'])
def file_upload():
    msg = ""
    if request.method == 'POST':
        if 'file' not in request.files:
            msg = 'No file part'
            print(msg)
            return render_template("index.html", msg=msg)
                    
        file = request.files['file']
        filename = file.filename
        if filename == '':
            msg = 'No selected file'
            print(msg)
            return render_template("index.html", msg=msg)
        
        if file:
            filepath=os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            msg = 'File uploaded successfully'
            print(msg)
            # return render_template("index.html", msg=msg)
            return redirect(url_for('configure', filename=filename))
    return render_template("index.html", msg=msg) 

if __name__ == '__main__':
	app.run(debug=True)