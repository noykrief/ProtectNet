read -sp "Enter the password for demo user: " PASSWORD

Green='\033[0;32m'
Color_Off='\033[0m'

echo -e "$Green"

echo "###########################################################"
echo "#####          Scanning ports on remote host          #####"
echo "###########################################################"
echo ""
echo "   $ sudo nmap -p 1-30 10.10.248.158"
sleep 5
echo ""
sudo nmap -p 1-30 10.10.248.158
echo ""
echo ""
sleep 5

echo "###########################################################"
echo "#####      Coppying attack script to remote host      #####"
echo "###########################################################"
echo ""
echo "   $ scp attack.sh demo@10.10.248.158:///home/demo/"
sleep 5
echo ""
sshpass -p $PASSWORD scp attack.sh demo@10.10.248.158:///home/demo/
echo ""
echo ""
sleep 5

echo -e "$Color_Off"
