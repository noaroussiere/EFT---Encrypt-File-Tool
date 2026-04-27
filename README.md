# How to use

Faire la génération des certificats

```bash
./generateKeys.sh
```

## Encrypt

Faire la demande des certificats public de vos corresondants

```bash
cargo build -r
./target/debug/encrypted_folders -i raw_data.file -o file_encrypted.eft \
    --public-key <chemin-certif-public-personne-distante-1> \
    --public-key <chemin-certif-public-personne-distante-2> \ # Optionel
    --encrypt
```

Envoyer vôtre fichier au correpondant

## Decrypt

Le correspondant peut decrypter le message ou fichier via cette commande qui va venir chercher le certificat dans ~/.eft/cert.pem

```bash
./target/release/encrypted_folders -i ./file_encrypted.eft -o raw_data.decrypt --decrypt
```
