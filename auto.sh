echo "note that this script syntax is : ./auto.sh [fichier] [key] [version]"
echo
echo "original file:"
cat -e $1
valgrind ./elcrypt -e -f $1 -o $1.enc -k $2 -$3
echo
echo "crypted file:"
cat -e $1.enc
valgrind ./elcrypt -d -f $1.enc -o $1.denc -k $2 -$3
echo
echo "decrypted file:"
cat -e $1.denc
