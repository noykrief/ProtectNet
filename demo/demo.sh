echo "###########################################################"
echo "#####          Scanning ports on remote host          #####"
echo "###########################################################"
echo ""
echo "   $ sudo nmap -p 1-30 10.10.248.158"
sleep 5
echo ""
sudo nmap -p 1 1-30 10.10.248.158
echo ""
echo ""
sleep 5


echo "###########################################################"
echo "#####        SSH into remote host as demo user        #####"
echo "###########################################################"
echo ""
echo "   $ ssh demo@10.10.248.158"
sleep 5
echo ""
sshpass -p 1 ssh -t demo@10.10.248.158 'sshpass -p 1 sudo /home/demo/attack.sh'
echo ""
echo ""
sleep 5
