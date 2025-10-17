<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Foundation\Auth\AuthenticatesUsers;  // Import du trait
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Illuminate\Validation\ValidationException;

class LoginController extends Controller
{

    use AuthenticatesUsers; //pour heriter les methodes

    // fonction register
    public function register(Request $request)
    {
        // a. Validation des champs
        $validatedData = $request->validate( [
        'name' => 'required|string|max:255',
        'email' => 'required|string|email|unique:users,email',
        'password' => 'required|string|min:6|confirmed',
    ],
    [
        'name.required' => 'Le nom est obligatoire.',
        'email.required' => 'L’email est obligatoire.',
        'email.email' => 'Veuillez entrer un email valide.',
        'email.unique' => 'Cet email existe déjà dans la base de données.',
        'password.required' => 'Le mot de passe est obligatoire.',
        'password.min' => 'Le mot de passe doit contenir au moins 6 caractères.',
        'password.confirmed' => 'Les mots de passe ne correspondent pas.',
    ]);

        // b. Création du nouvel utilisateur
        $user = User::create([
            'name' => $validatedData['name'],
            'email' => $validatedData['email'],
            'password' => Hash::make($validatedData['password']),
        ]);

        // c. Génération du token Sanctum
        $token = $user->createToken('auth_token')->plainTextToken;

        // d. Retourner la réponse JSON
        return response()->json([
            'status' => 200,
            'message' => 'Utilisateur créé avec succès',
            'user' => $user,
            'token' => $token,
            'token_type' => 'Bearer',
        ], 200);
    }

     // fonction login Aussi important
    //  public function login(Request $request)
    // {
    //     // a) Validate the request
    //     $credentials = $request->validate([
    //         'email' => 'required|string|email',
    //         'password' => 'required|string|min:6',
    //     ]);

    //     // b) Check if it matches (user exists and password ok)
    //     $user = User::where('email', $credentials['email'])->first();

    //     if (! $user || ! Hash::check($credentials['password'], $user->password)) {
    //         // On peut renvoyer 401
    //         return response()->json([
    //             'message' => 'Identifiants invalides.'
    //         ], 401);
    //     }

    //     // Optionnel : supprimer les anciens tokens si tu veux forcer single session
    //     // $user->tokens()->delete();

    //     // c) Create token and return data + bearer token
    //   //  $tokenName = $request->header('User-Agent') ?? 'mobile-token';

    //     $plainTextToken = $user->createToken('auth_token')->plainTextToken;

    //     return response()->json([
    //         'message' => 'Authentification réussie.',
    //         'user' => [
    //             'id' => $user->id,
    //             'name' => $user->name,
    //             'email' => $user->email,
    //             // n'ajoute jamais le password ici
    //         ],
    //         // retourne le token (côté client, utiliser "Authorization: Bearer {token}")
    //         'token' => $plainTextToken,
    //         'token_type' => 'Bearer',
    //     ], 200);
    // }

    public function login(Request $request)
{
    $validated = $request->validate([
        'email' => 'required|email',
        'password' => 'required',
    ]);

    // Vérifie si l'utilisateur existe
    $user = User::where('email', $validated['email'])->first();

    if (!$user) {
        return response()->json([
            'status' => false,
            'message' => 'Adresse e-mail incorrecte.',
        ], 401);
    }

    // Vérifie le mot de passe
    if (!Hash::check($validated['password'], $user->password)) {
        return response()->json([
            'status' => false,
            'message' => 'Mot de passe incorrect.',
        ], 401);
    }

    // Tout est OK → Génère le token
    $token = $user->createToken('auth_token')->plainTextToken;

    return response()->json([
        'status' => true,
        'message' => 'Connexion réussie.',
        'user' => $user,
        'token' => $token,
    ], 200);
}

}
