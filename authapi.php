<?php

// Autoriser les requêtes cross-origin (CORS) pour le frontend
header("Access-Control-Allow-Origin: https://liverpool.alwaysdata.net");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

// Réponse rapide pour les requêtes OPTIONS (prévolée par le navigateur pour CORS)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

require_once 'jwt_utils.php';
require_once 'connexionDB.php'; // Connexion à la BDD séparée

// -----------------------------------------------------------------------
// GET — Validation d'un token JWT envoyé par le frontend
// Vérifie signature et expiration du token
// -----------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'GET') {

    $headers = getallheaders();
    $jwt = isset($headers['Authorization']) ? str_replace('Bearer ', '', $headers['Authorization']) : null;

    if (!$jwt) {
        deliver_response(401, "Unauthorized", "Token manquant");
        exit;
    }

    $secret = "secret_key";

    // Vérifie signature et expiration
    if (!is_jwt_valid($jwt, $secret)) {
        deliver_response(401, "Unauthorized", "Token invalide ou expiré");
        exit;
    }

    $payload = get_jwt_payload($jwt);

    deliver_response(200, "Token valide", [
        'login' => $payload['login'] ?? null,
        'role'  => $payload['role']  ?? null,
    ]);
    exit;
}

// -----------------------------------------------------------------------
// POST — Connexion : vérifier login/mot de passe et générer un JWT
// -----------------------------------------------------------------------
function seConnecter() {
    global $linkpdo;

    $error = null;

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $input = json_decode(file_get_contents("php://input"), true);

        $login    = $input['login']    ?? null;
        $password = $input['password'] ?? null;

        if (!empty($login) && !empty($password)) {
            $user = isValidUser($login, $password, $linkpdo);

            if ($user) {
                // Création du token JWT avec payload et expiration
                $headers = ['alg' => 'HS256', 'typ' => 'JWT'];
                $payload = [
                    'login' => $login,
                    'role'  => $user['role'],
                    'exp'   => time() + 3600
                ];

                $jwt = generate_jwt($headers, $payload, "secret_key");
                header("Authorization: Bearer $jwt"); // Ajoute le token aux headers de la réponse
                deliver_response(200, "Authentification réussie", $jwt);
            } else {
                $error = 'Login et/ou mot de passe incorrectes';
            }
        } else {
            $error = 'Les champs login et mot de passe sont obligatoires';
        }
    } else {
        // Méthode non POST : erreur 405
        deliver_response(405, "Method Not Allowed", "Méthode non autorisée");
        exit;
    }

    return $error ?? null;
}

// Vérifie en BDD si login et mot de passe correspondent
function isValidUser($login, $password, $linkpdo) {
    $query = "SELECT password, role FROM authentification WHERE login = :login"; 
    $stmt = $linkpdo->prepare($query);
    $stmt->execute(['login' => $login]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password'])) {
        return $user; 
    }
    return false;
}

// Appel de la fonction connexion et traitement de l'erreur
$resultError = seConnecter();
if ($resultError) {
    deliver_response(401, "Unauthorized", $resultError);
}
?>