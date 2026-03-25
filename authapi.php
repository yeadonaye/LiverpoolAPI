<?php
    require_once 'jwt_utils.php';
    require_once 'connexionDB.php'; // Nous utilisons une BD à part

    function seConnecter() {
    global $linkpdo;

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $login = $_POST['login'] ?? null;
        $password = $_POST['password'] ?? null;

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
                deliver_response('200', 'Authentification réussie', $jwt);
            } else {
                $error = 'Login et/ou mot de passe incorrectes';
            }
        } else {
            $error = 'Les champs login et password sont obligatoires!!';
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
        deliver_response(401, $resultError);
    }
?>