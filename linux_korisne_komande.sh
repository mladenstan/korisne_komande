rpm -qa | grep ime_paketa ------------------> provera sta je instalirano
yum list available | grep ime_paketa--------> sta je dostupno
ps -U drutt | wc -l ------------------------> prikazuje koje procese je korisnik pokrenuo sa PID - om i broji ih
lsof | grep drutt | wc -l ------------------> izlistaj otvorene fajlove koje je otvorio korisnik i izbroj
top -u drutt -------------------------------> pa kada si u top programu pristisni shift + o 
strace -o /home/gabgarmar/logovanje.log su - drutt ----------> loguje komandu
more /etc/timezone ------------------------------------------> pregled timezone
sudo dpkg-reconfigure tzdata --------------------------------> konfiguracija timezone na ubuntu
logrotate -dv /path/to/configfile -------------------> pokrenuti logrotate bez izmena fajlova dobar za dijagnostiku
logrotate -f /path/to/configfile --------------------> pokrenuti vanredni logrotate
id -u -----------------------------------------------> provera id usera
sudo lsof -i -------------------------------> koji su otvoreni portovi
sudo netstat -lptu -------------------------> koji su otvoreni portovi
sudo netstat -tulpn ------------------------> koji su otvoreni portovi
netstat -ano -------------------------------> windows komanda :-)
du -ksh * vidi sta radi
openssl rsa -in privateKey.key -check -------------------> provera kljuca
openssl x509 -in certificate.crt -text -noout -----------> provera sertifikata
usermod --home /home/mladen/ mladen ---------------------> podesava home path za vec postojeceg usera mladen
cat /etc/issue ------------------------------------------> provera verzije SUSE - a 
ntpq -p -------------------------------------------------> sinhronizacija vremena na ntp
ntpdate adresa_ntp_servera ------------------------------> sinhronizacija vremena sa ntpdate
find / -name main.php
find / -name ".php"
našao sam putanju /export/home/vpngui/htdocs/user/main.php
cat /etc/passwd | cut -d: -f1 ---------------------------> izlistava sve user - e
cat /etc/group |cut -d: -f1 -----------------------------> izlistava sve grupe
grep 'grpup-name-here' /etc/group -----------------------> izlistava sve članove grupe
groups ime-usera ----------------------------------------> izlistava grupe gde je korisnik učlanjen
htpasswd -c password-file username
useradd -m -d /export/home/automic automic --------------> Pravljenje usera automic sa home - om na Solaris - u
gunzip -c ucxjui8.tar.gz | tar xvf -   ekstrakt fajla na solarisu tar.gz
ps -p $$ ------------------------------------------------> provera koji je default shell
whereis ksh ---------------------------------------------> gde se nalazi servis
chsh -s /bin/ksh UserNameHere ---------------------------> podesavanje default - nog shell - a 
export PATH=/home/automic/Java/jre1.7.0/bin:$PATH
/home/automic/Java/jre1.7.0/bin
last | more - provera ko je se kacio
/etc/httpd/modules/ -------------------------------------> ovde se nalaze svi moduli koje apache ucitava
### Dodavanje user-a sudo ########################################
visudo                                                           #
# Odkomentarisatu linuju                                         #
## Allows people in group wheel to run all commands              #
# %wheel        ALL=(ALL)       ALL                              #
usermod -aG wheel gabgarmar                                      #
su - gabgarmar       											 #
#																 #
# ili															 #
gabgarmar    ALL=(ALL)       ALL								 #
#                                               				 #
# proveriti sa komandom groups da li se user nalazi u wheel grupi#
##################################################################

du -hs --------------------------------------------------> pregled velicine direktorijuma


pgrep -u $USER -x ucybsmgr ------------------------------> getpid


### IPTABLES ####################
INPUT chain – Incoming to firewall. For packets coming to the local server.
OUTPUT chain – Outgoing from firewall. For packets generated locally and going out of the local server.
FORWARD chain – Packet for another NIC on the local server. For packets routed through the local server.

iptables -A INPUT -s 192.168.1.1 -j DROP -----------------> drop-uje sav saobracaj sa adrese 192.168.1.1
-A - Append this rule to a rule chain   -----------------> Dodaje liniju u lanac, ako ovako postavimo stavice je na kraj lanca u nasem slucaju INPUT
-s - Source address[/mask] source specification ---------> Definise source adresu u nasem slucaju je 192.168.1.1
-j - Jump to the specified target. By default, iptables allows four targets: 
	1.ACCEPT - Accept the packet and stop processing rules in this chain. 
	2.REJECT - Reject the packet and notify the sender that we did so, and stop processing rules in this chain. 
	3.DROP - Silently ignore the packet, and stop processing rules in this chain. 
	4.LOG - Log the packet, and continue processing more rules in this chain. Allows the use of the --log-prefix and --log-level options.

iptables -I INPUT 1 -s 192.168.1.1 -j DROP ---------------> drop-uje sav saobracaj sa adrese 192.168.1.1
-I - Inserts a rule - dodaje liniju u lanac u našem slučaju staviće je na prvo mesto u lanac INPUT

iptables -A INPUT -p tcp -s 192.168.1.1 --dport 22 -j DROP ---> Dropuje saobraćaj sa adrese po portu 22

iptables -L -n -v --line-numbers ------------------------> Izlistava rulove zajedno sa rednim brojevima linija
iptables -D INPUT 4 -------------------------------------> Brise cetvrtu liniju iz INPUT lanca
iptables -D INPUT -s 192.168.1.1 -j DROP -----------------> Brise ovu liniju iz INPUT lanca

!!! Veoma je bitno ako stavljamo ako imamo ACCEPT all da pre toga stavimo DROP ako hoćemo neku pojedinačnu adresu
Najbolja praksa je na početku DROP-ovati sve pa pojedinačno dodavati source adrese sa kojih može da se pristupa

service iptables save -----------------------------------> Snimanje konfiguracije
#################################


last reboot -F - ispisuje kad se server restartova zajedno sa vremenom i datumom

usermod -a -G mqm mladenstan - dodavanje user-a u postojeću grupu

### Funkcija koja nalazi PID naseg procesa #####################
getpid ()
{
   PID=`pgrep -u root -x ucybsmgr`
   echo " Automic ServiceManager runs with PID: $PID"     
}

runas /u:it\esbecms cmd - otvara cmd kao drugi user
################################################################


ps axo pid,ppid,rss,vsz,nlwp,cmd - gledanje tredova po procesu
netstat -an | grep :7800 | wc -l - broji koliko ima konekcija po određenom portu
free -m | grep buffers/cache | cut -c26-29 - prikazuje realno iskorišćenost memorije
/usr/sbin/logrotate -v verbose samo da vidimo šta se radi kada ide log rotate
/usr/sbin/logrotate -d debug pokreće se log rotate ali se ne izvršava
/usr/sbin/logrotate -f force pokreće se log rotate i izvršava


#######################################
ldd -  is a Linux utility that is used in case a user wants to know the shared library dependencies of an executable or even that of a shared library. 

Basic example to find the dependency of an executable or shared library. 

In the above examples we tried to run the ldd command on an executable ‘redis-server’ and a shared library ‘linux-vdso.so and as you can see that the ldd command output provided the shared library dependencies.
#######################################

ntsysv utility - is a command-line application with a simple text user interface to configure which services are to be started in selected runlevels.

netstat -nlpt

service nginx configtest - provera parametara preko startup skripte

userdel -r rros - brisanje user-a i njegovog home direktorijuma

# Kopiranje velike količine fajlova
nohup find . -print -depth | cpio -pdm /u02 &

# Kopiranje celih foldera
# -a : Preserve the specified attributes such as directory an file mode, ownership, timestamps, if possible additional attributes: context, links, xattr, all.
# -v : Explain what is being done.
# -r : Copy directories recursively
cp -avr /opt/IBM/logs /home/mladen/logs

# Tarovanje fajlova i foldera
# -c : Create a tar ball.
# -v : Verbose output (show progress).
# -f : Output tar ball archive file name.
# -x : Extract all files from archive.tar.
# -t : Display the contents (file list) of an archive.
tar -cvf output.tar /dirname
tar -cvf output.tar /dirname1 /dirname2 filename1 filename2

# Tar fajlova i zipovanje
# -z : Compress archive using gzip program
# -c: Create archive
# -v: Verbose i.e display progress while creating archive
# -f: Archive File name
tar -zcvf archive-name.tar.gz directory-name
tar -zcvf logs_kabpptest.tar.gz logs

# Alijasi
I would check if your rm is an alias. Typing alias at the command line you will see all defined aliases. I expect something like 
alias rm='rm -i'

If so, the alias is probably defined in in ~/.bashrc, so you can remove the alias altogether or change it to suit your needs.

Alternatively, you can remove the alias for the current terminal session using
unalias rm

# Najvećih pet foldera na /root particiji
du -a / | sort -n -r | head -n 5

# Najvećih pet foldera na trenutnoj putanji
du -a | sort -n -r | head -n 5

# Najvećih pet fajlova na sistemu
find -type f -exec du -Sh {} + | sort -rh | head -n 5

# URL
http://www.tecmint.com/find-top-large-directories-and-files-sizes-in-linux/

# Ivanine komande
du -hsx * | sort -r | head -10 
du -sh * | sort -n 

# Instalacija paketa iz tekstualnog fajla
for a in `cat test.txt`; do yum install -y $a; done

# Kopiranje fajlova iz komande find
for a in `find /home/admbus/deploy/20170214 -name "*_TST.properties"`; do cp $a /home/admbus/deploy/20170309; done

# primenjivanje BAR fajlova
for a in `ls *.bar`; do b=`echo $a | sed -e 's/.bar/_TST.properties/g'`; echo;  echo "---------- Primenjujem propertie fajl ${b} na ${a} "----------; mqsiapplybaroverride -b $a -p $b -r; done > properties.log

# Vrednost poslednje komande
echo $?

# Kreiranje home direktorijuma za user-a koji vec postoji
usermod -d /home/mladen/ mladen

# Add a new user to primary group
useradd -g developers tony
id tony
# Please note that small g (-g) option add user to initial login group (primary group). The group name must exist. A group number must refer to an already existing group.

useradd -G admins,ftp,www,developers jerry
# Please note that capital G (-G) option add user to a list of supplementary groups. Each group is separated from the next by a comma, with no intervening whitespace. For example, add user jerry to groups admins, ftp, www, and developers, enter:

# Add a existing user to existing group
# Add existing user tony to ftp supplementary/secondary group with the usermod command using the -a option ~ i.e. add the user to the supplemental group(s). Use only with -G option:
usermod -a -G ftp tony

# In this example, change tony user’s primary group to www, enter:
usermod -g www tony

# Parametri
-a Add the user to the supplementary group(s). Use only with the -G option. 
-g Use this GROUP as the default group. 
-G Add the user to GRP1,GRP2 secondary group. 

# Provera verzije na SuSE-u
cat /etc/SuSE-release

# Provera međuzavisnosti
rpm -qR ime_instaliranog_paketa
rpm -qpR ime_paketa # Ovo je ok komanda

# For petlja prikaz sadržaja svih fajlova iz foldera
for file in /mnt/c/Users/mladenstan/Desktop/vazne_stvari/IB/properties_fajlovi/propertiesTST/*; do echo "Ime fajla je $file"; cat "$file"; echo ; done
# ili
for file in /mnt/c/Users/mladenstan/Desktop/vazne_stvari/IB/properties_fajlovi/propertiesTST/*
do
	echo "Ime fajla je $file"
	cat "$file"
	echo
done

# Kreiranje foldera sa odre]enim GUID-om
mkdir --mode=u+rwxs,g+rs,g-w,o-rwx test

# Komanda daje id okruženja u kome se izvršava
$$

# Na redhat i CentOS hostname se setuje u fajlu /etc/sysconfig/network potrebno je uraditi restart mreže
NETWORKING=yes
HOSTNAME=KALINUXAPPTEST

# Promena bash-a za postojećeg user-a
usermod -s /bin/bash mladen

# Brisanje sve iz reda nakon prvog space-a
sed 's/\s.*$//' maven_download_obrada.txt > maven_konacno.txt

# Da na ubuntu vidimo koji paketi čekaju na update
sudo apt-get upgrade --dry-run

# Da proverimo koji je link za kloniranje GIT repozitorijuma
cat .git/config

# Prosleđivanje promenljivih pri pokretanju skripte
Prva promenljiva posle naziva skripte je $1 sa tom promenljivom prosleđujemo jedan string ako postoje dve reči razdvojene prikazaće samo jednu. To se može rešiti ako stavimo dve reči pod duple navodnike. Tada će obe reči biti u promenljivoj $1. Ovo se ne odnosi ako ispred druge reči postoji $ znak jel će onda bash pokušati da zameni vrednost

# Da bi videli da li fajl postoji možemo da koristimo
[[ -a ili -e ili -f]]

# Ovde gledamo da li fajl ne postoji
[[ ! -a ili ! -e ili ! -f]]

# Slanje greške u bezdan
Ako hoćemo da izbrišemo fajl a on ne postoji možemo da koristimo komandu rm nesto.txt > /dev/null i nećemo dobiti grešku

# Dodavanje gruge komande
ako kažemo ovako rm nesto.txt > /dev/null && echo "File exists and was removed" ako stvarno fajl ne postoji nećemo dobiti grešku ali nam se naša komanda echo neće izvršiti zato što je prva komanda prsla

# A možemo i ovako
rm nesto.txt > /dev/null && echo "File exists and was removed" || echo "File does not exist and cannot be deleted"

# 25 korisnih apt-get komandi
https://www.tecmint.com/useful-basic-commands-of-apt-get-and-apt-cache-for-package-management/

# Pregled velicine sortiranih foldera
du -hs /var/lib/docker/* | sort -h

