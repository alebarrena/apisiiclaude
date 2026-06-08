<?php

namespace App\Http\Controllers\Sii\RCV;

use App\Http\Controllers\Controller;
use App\Http\Controllers\Sii\Sii;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class SalesController extends Controller
{
    use ValidatesRcvInput;

    public function diary($day, $month, $year, Request $request): JsonResponse
    {
        if ($error = $this->validateCredentials($request)) return $error;
        if ($error = $this->validatePeriod($month, $year)) return $error;
        if ($error = $this->validateDay($day))              return $error;

        $rut    = $request->input('RutUsuario');
        $pass   = $request->input('PasswordSII');
        $detail = $request->input('Detallado', false);

        try {
            $sii = new Sii($rut, $pass);
            $rr  = explode("-", $rut);
            $dd  = $sii->summary($rr[0], $rr[1], $day, $month, $year, "REGISTRO", "VENTA", $detail);
        } catch (\RuntimeException $e) {
            $status = str_contains($e->getMessage(), 'inválidas') ? 401 : 502;
            return response()->json(['error' => $e->getMessage()], $status);
        }

        $date    = implode("/", [$day, $month, $year]);
        $details = [];
        foreach ($dd['ventas']['detalleVentas'] as $vv) {
            if ($vv['fechaEmision'] === $date) {
                $details[] = $vv;
            }
        }
        $dd['ventas']['detalleVentas'] = $details;

        return response()->json($dd);
    }

    public function montly($month, $year, Request $request): JsonResponse
    {
        if ($error = $this->validateCredentials($request)) return $error;
        if ($error = $this->validatePeriod($month, $year)) return $error;

        $rut    = $request->input('RutUsuario');
        $pass   = $request->input('PasswordSII');
        $detail = $request->input('Detallado', false);

        try {
            $sii = new Sii($rut, $pass);
            $rr  = explode("-", $rut);
            $result = $sii->summary($rr[0], $rr[1], null, $month, $year, "REGISTRO", "VENTA", $detail);
        } catch (\RuntimeException $e) {
            $status = str_contains($e->getMessage(), 'inválidas') ? 401 : 502;
            return response()->json(['error' => $e->getMessage()], $status);
        }

        return response()->json($result);
    }
}
