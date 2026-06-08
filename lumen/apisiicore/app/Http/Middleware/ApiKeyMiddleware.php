<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class ApiKeyMiddleware
{
    public function handle(Request $request, Closure $next): mixed
    {
        $apiKey = env('API_KEY');

        if (!$apiKey) {
            return response()->json(['error' => 'API_KEY no configurada en el servidor'], 500);
        }

        if ($request->header('X-Api-Key') !== $apiKey) {
            return response()->json(['error' => 'API key inválida o ausente'], 401);
        }

        return $next($request);
    }
}
