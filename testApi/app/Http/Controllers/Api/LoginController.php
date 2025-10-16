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

     public function login(Request $request)
    {
        // a) Validate the request
        $credentials = $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string|min:6',
        ]);

        // b) Check if it matches (user exists and password ok)
        $user = User::where('email', $credentials['email'])->first();

        if (! $user || ! Hash::check($credentials['password'], $user->password)) {
            // On peut renvoyer 401
            return response()->json([
                'message' => 'Identifiants invalides.'
            ], 401);
        }

        // Optionnel : supprimer les anciens tokens si tu veux forcer single session
        // $user->tokens()->delete();

        // c) Create token and return data + bearer token
      //  $tokenName = $request->header('User-Agent') ?? 'mobile-token';

        $plainTextToken = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'message' => 'Authentification réussie.',
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                // n'ajoute jamais le password ici
            ],
            // retourne le token (côté client, utiliser "Authorization: Bearer {token}")
            'token' => $plainTextToken,
            'token_type' => 'Bearer',
        ], 200);
    }
}
