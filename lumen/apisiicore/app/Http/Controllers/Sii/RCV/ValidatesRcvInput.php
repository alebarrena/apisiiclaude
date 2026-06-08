<?php

namespace App\Http\Controllers\Sii\RCV;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

trait ValidatesRcvInput
{
    private function validateCredentials(Request $request): ?JsonResponse
    {
        $rut  = $request->input('RutUsuario');
        $pass = $request->input('PasswordSII');

        if (!$rut || !$pass) {
            return response()->json(
                ['error' => "Los campos 'RutUsuario' y 'PasswordSII' son obligatorios."],
                422
            );
        }

        if (!preg_match('/^\d{1,8}-[\dkK]$/', $rut)) {
            return response()->json(
                ['error' => "Formato de RUT inválido. Use el formato: 12345678-9"],
                422
            );
        }

        return null;
    }

    private function validatePeriod(string $month, string $year): ?JsonResponse
    {
        if (!preg_match('/^(0?[1-9]|1[0-2])$/', $month)) {
            return response()->json(
                ['error' => "Mes inválido. Use un valor entre 1 y 12."],
                422
            );
        }

        if (!preg_match('/^(19|20)\d{2}$/', $year)) {
            return response()->json(
                ['error' => "Año inválido. Use un año de 4 dígitos."],
                422
            );
        }

        return null;
    }

    private function validateDay(string $day): ?JsonResponse
    {
        if (!preg_match('/^(0?[1-9]|[12]\d|3[01])$/', $day)) {
            return response()->json(
                ['error' => "Día inválido. Use un valor entre 1 y 31."],
                422
            );
        }

        return null;
    }
}
