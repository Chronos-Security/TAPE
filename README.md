# TAPE
TAPE (Tmux Automated Pentesting Enumeration) is a script used to organize and automate the pentest process

<br>

### Installation process
Install required programs:
```bash
sudo apt install -y git terminator seclists ldap-utils 
pip install -r requirements.txt
```
Download the script from GitHub
```bash
git clone https://github.com/ChronosPK/TAPE.git
cd TAPE
sudo python3 tape.py -h
```

<br>

### Modify the commands
I added some basic commands I already use when encountering common services. <br>
You are free to add your commands for each network protocol.

### How to run
```bash
# sudo privileges since some scripts might need elevated privileges
sudo python3 tape.py -h
```
