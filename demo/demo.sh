echo "Scanning ports on remote host 10.10.248.158"
echo $PASSWORD | sudo -S nmap -p 1-30 10.10.248.158

sleep 2

echo "SSH into remote host 10.10.248.158 as demo user"
sshpass -p 1 ssh -t demo@10.10.248.158 'echo 1 | sudo -S /home/cs401/ProtectNet/demo/attack.sh'
