<?php

    // Autoriser les requete cross-origin
    header("Access-Control-Allow-Origin: https://liverpool.alwaysdata.net");
    header("Access-Control-Allow-Methods: POST, OPTIONS");
    header("Access-Control-Allow-Headers: Content-Type, Authorization");

    // Au cas où le client envoie une requete OPTIONS, on répend directement avec un code 200 pour dire que tout est ok
    // Quand le frontend fait une requete (POST, PUT, DELETE) vers une API qui est sur un autre domaine, le navigateur envoie d'abord une requete OPTIONS pour vérifier si le serveur autorise les requetes venant d'autre origines (CORS). Si le serveur répond avec les bons headers, alors le navigateur envoie la requete réelle (POST, PUT, DELETE).
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(200);
        exit;
    }

    require_once 'jwt_utils.php';
    require_once 'connexionDB.php'; // Nous utilisons une BD à part

    function seConnecter() {
    global $linkpdo;

    $error = null;

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $input = json_decode(file_get_contents("php://input"), true);

        $login = $input['login'] ?? null;
        $password = $input['password'] ?? null;

        if (!empty($login) && !empty($password)) {
            $user = isValidUser($login, $password, $linkpdo);

            if ($user) {
                $headers = ['alg'=>'HS256','typ'=>'JWT'];
                $payload = [
                    'login' => $login,
                    'role'  => $user['role'],
                    'exp'   => time() + 3600
                ];

                $jwt = generate_jwt($headers, $payload, "secret_key");
                header("Authorization: Bearer $jwt"); // Pour ajouter le token dans les headers de la réponse
                deliver_response(200, "Authentification réussie", $jwt);
            } else {
                $error = 'Login et/ou mot de passe incorrectes';
            }
        } else {
            $error = 'Les champs login et mot de passe sont obligatoires';
        }
    }

    return $error ?? null;
    }

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

    $resultError = seConnecter();
    if ($resultError) {
        deliver_response(401, "Unauthorized", $resultError);
    }
?>