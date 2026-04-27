use clap::Parser;
use std::env;
use std::fs;
use std::io::Write;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm,
};
use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey, Oaep};
use rsa::pkcs8::{DecodePublicKey, DecodePrivateKey}; 
use sha2::Sha256;

// ==========================================
// CONFIGURATION DE LA LIGNE DE COMMANDE (CLAP)
// ==========================================
#[derive(Parser, Debug)]
#[command(name = "Encrypted file tool", version = "1.0")]
struct Args {
    #[arg(short, long, conflicts_with = "decrypt")]
    encrypt: bool,

    #[arg(short, long, conflicts_with = "encrypt")]
    decrypt: bool,

    #[arg(short, long)]
    input: String,

    #[arg(short, long)]
    output: String,

    #[arg(long = "public-key")]
    public_keys: Vec<String>,
}

fn main() {
    let args = Args::parse();
    let mut rng = OsRng;

    // 1. Récupération dynamique du dossier utilisateur (ex: /home/roussierenoa)
    let home_dir = env::var("HOME").expect("Impossible de trouver la variable d'environnement HOME");

    // (Garde le début de ton main et la variable home_dir)

    if args.encrypt {
        if args.public_keys.is_empty() {
            panic!("❌ Tu dois fournir au moins une --public-key pour chiffrer !");
        }

        let data = fs::read(&args.input).unwrap();
        let aes_key = Aes256Gcm::generate_key(&mut rng);
        let nonce = Aes256Gcm::generate_nonce(&mut rng);
        let cipher = Aes256Gcm::new(&aes_key);
        
        let ciphertext = cipher.encrypt(&nonce, data.as_ref()).unwrap();

        // NOUVEAU : On prépare le fichier de sortie
        let mut out = fs::File::create(&args.output).unwrap();
        out.write_all(&nonce).unwrap();

        // On écrit le nombre de destinataires (converti en 4 octets)
        let nb_destinataires = args.public_keys.len() as u32;
        out.write_all(&nb_destinataires.to_le_bytes()).unwrap();

        // On boucle sur CHAQUE clé publique fournie par l'utilisateur
        for pub_path in &args.public_keys {
            let chemin_absolu = pub_path.replace("~", &home_dir);
            let pub_pem = fs::read_to_string(&chemin_absolu).expect(&format!("Impossible de lire {}", chemin_absolu));
            let public_key = RsaPublicKey::from_public_key_pem(&pub_pem).expect("Clé publique invalide");

            // On chiffre LA MÊME clé AES pour cette personne
            let encrypted_aes_key = public_key.encrypt(&mut rng, Oaep::new::<Sha256>(), aes_key.as_slice()).unwrap();
            
            // On écrit cette "serrure" dans le fichier
            out.write_all(&encrypted_aes_key).unwrap();
            println!("✅ Accès ajouté pour : {}", pub_path);
        }

        // On termine en écrivant les vraies données
        out.write_all(&ciphertext).unwrap();
        println!("🔒 Fichier chiffré avec succès !");
        
    } else if args.decrypt {
        let priv_path = "~/.eft/cert.pem";
        let chemin_absolu = priv_path.replace("~", &home_dir);
        let priv_pem = fs::read_to_string(&chemin_absolu).expect("Impossible de lire la clé privée");
        let private_key = RsaPrivateKey::from_pkcs8_pem(&priv_pem).expect("Format de clé privée invalide");

        let archive_data = fs::read(&args.input).expect("Impossible de lire l'archive .zed");

        let nonce_bytes = &archive_data[0..12];
        
        // NOUVEAU : Lire combien de "serrures" il y a
        let nb_destinataires = u32::from_le_bytes(archive_data[12..16].try_into().unwrap());
        
        println!("Ce fichier possède {} accès configurés. Recherche de votre accès...", nb_destinataires);

        // On va essayer d'ouvrir les serrures une par une
        let mut offset = 16;
        let mut aes_key_bytes = None; // Contiendra la clé AES si on réussit

        for i in 0..nb_destinataires {
            let encrypted_aes_key = &archive_data[offset..offset+512]; // Bloc de 512 octets (RSA-4096)
            
            let padding = Oaep::new::<Sha256>();
            // On essaie de déchiffrer. Si ça marche, on sauvegarde la clé et on stop la boucle !
            if let Ok(cle_dechiffree) = private_key.decrypt(padding, encrypted_aes_key) {
                println!("🔓 Votre accès a été trouvé (Serrure n°{}) !", i + 1);
                aes_key_bytes = Some(cle_dechiffree);
                break; 
            }
            // Si ça rate, on avance au bloc suivant
            offset += 512;
        }

        // Si la boucle s'est terminée et qu'on a toujours pas la clé...
        let aes_key_bytes = aes_key_bytes.expect("❌ Accès refusé : Votre clé privée ne correspond à aucun accès pour ce fichier.");

        // --- LA CORRECTION EST ICI ---
        // On calcule exactement où commencent les vraies données, 
        // peu importe à quel moment la boucle s'est arrêtée !
        // 12 (Nonce) + 4 (Compteur) = 16. Auquel on ajoute (Nombre de destinataires * 512 octets).
        let debut_donnees = 16 + (nb_destinataires as usize * 512);
        
        let donnees_chiffrees = &archive_data[debut_donnees..]; 
        // -----------------------------

        let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
        let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new(aes_key);

        let plaintext = cipher.decrypt(nonce, donnees_chiffrees)
            .expect("❌ Échec AES : Données corrompues");

        fs::write(&args.output, plaintext).unwrap();
        println!("✅ Fichier déchiffré avec succès : {}", args.output);
    } else {
        println!("⚠️ Tu dois spécifier --encrypt ou --decrypt !");
    }
}