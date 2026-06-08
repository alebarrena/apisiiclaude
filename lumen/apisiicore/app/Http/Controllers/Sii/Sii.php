<?php

namespace App\Http\Controllers\Sii;

class Sii
{
    public string $user;
    public string $password;
    public array $session_data;

    public function __construct(string $user, string $pass)
    {
        $this->user     = $user;
        $this->password = $pass;
        $this->login($user, $pass);
    }

    public function login(string $user, string $pass): void
    {
        $rr      = explode("-", $user);
        $rut     = $rr[0];
        $dv      = $rr[1];
        $rutcntr = str_replace(",", ".", number_format($rut)) . "-" . $dv;

        $curl = curl_init();
        curl_setopt_array($curl, [
            CURLOPT_URL            => 'https://zeusr.sii.cl/cgi_AUT2000/CAutInicio.cgi',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING       => '',
            CURLOPT_MAXREDIRS      => 10,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_1_1,
            CURLOPT_COOKIESESSION  => true,
            CURLOPT_HEADER         => 1,
            CURLOPT_CUSTOMREQUEST  => 'POST',
            CURLOPT_POSTFIELDS     => 'rut=' . $rut . '&dv=' . $dv . '&referencia=https%3A%2F%2Fmisiir.sii.cl%2Fcgi_misii%2Fsiihome.cgi&411=&rutcntr=' . $rutcntr . '&clave=' . $pass,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
        ]);

        $response = curl_exec($curl);

        if (curl_errno($curl)) {
            $error = curl_error($curl);
            curl_close($curl);
            throw new \RuntimeException('Error de conexión al SII: ' . $error);
        }
        curl_close($curl);

        $cookies = [];
        preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $response, $matches);
        foreach ($matches[1] as $item) {
            parse_str($item, $cookie);
            $cookies = array_merge($cookies, $cookie);
        }

        // Verificar que el login fue exitoso comprobando las cookies críticas
        $required = ['TOKEN', 'CSESSIONID', 'NETSCAPE_LIVEWIRE_rut', 'NETSCAPE_LIVEWIRE_dv'];
        foreach ($required as $key) {
            if (empty($cookies[$key])) {
                throw new \RuntimeException('Credenciales SII inválidas o servicio no disponible.');
            }
        }

        $this->session_data = $cookies;
    }

    public function details(string $ptributario, string $estadoContab, string $operacion): array
    {
        $endpoint = $operacion === "COMPRA" ? "getDetalleCompraExport" : "getDetalleVentaExport";

        $body = json_encode([
            "metaData" => [
                "namespace"      => "cl.sii.sdi.lob.diii.consdcv.data.api.interfaces.FacadeService/" . $endpoint,
                "conversationId" => $this->session_data['TOKEN'],
                "transactionId"  => "568ed82b-1a07-45ec-93ef-0d1c7466fb3c",
                "page"           => null,
            ],
            "data" => [
                "rutEmisor"    => $this->session_data['NETSCAPE_LIVEWIRE_rut'],
                "dvEmisor"     => $this->session_data['NETSCAPE_LIVEWIRE_dv'],
                "ptributario"  => $ptributario,
                "codTipoDoc"   => 0,
                "operacion"    => $operacion,
                "estadoContab" => $estadoContab,
            ],
        ]);

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'https://www4.sii.cl/consdcvinternetui/services/data/facadeService/' . $endpoint);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        curl_setopt($ch, CURLOPT_ENCODING, 'gzip, deflate');
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $this->buildHeaders());

        $result = curl_exec($ch);

        if (curl_errno($ch)) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new \RuntimeException('cURL error en details(): ' . $error);
        }
        curl_close($ch);

        $data = json_decode($result, true);

        if (!is_array($data) || !isset($data['data']) || !is_array($data['data'])) {
            throw new \RuntimeException(
                'Respuesta inesperada del SII en details(). Posible sesión expirada o servicio no disponible.'
            );
        }

        $details = [];

        foreach ($data['data'] as $k => $dd) {
            if ($k === 0) continue;

            foreach (explode("\n", $dd) as $ddd) {
                $vvv = explode(";", $ddd);

                if ($operacion === "COMPRA") {
                    if ($vvv[0] === '') {
                        $details[count($details) - 1]['otrosImpuestos'][] = [
                            "codigoOtroImpuesto" => $vvv[24],
                            "valorOtroImpuesto"  => $vvv[25],
                            "tasaOtroImpuesto"   => $vvv[26],
                        ];
                    } else {
                        $details[] = [
                            "tipoDTE"                    => $vvv[1],
                            "tipoCompra"                 => $vvv[2],
                            "rutProveedor"               => $vvv[3],
                            "razonSocial"                => $vvv[4],
                            "folio"                      => $vvv[5],
                            "fechaEmision"               => $vvv[6],
                            "fechaRecepcion"             => $vvv[7],
                            "montoExento"                => $vvv[9],
                            "montoNeto"                  => $vvv[10],
                            "montoIvaRecuperable"        => $vvv[11],
                            "montoIvaNoRecuperable"      => $vvv[12],
                            "codigoIvaNoRecuperable"     => $vvv[13],
                            "montoTotal"                 => $vvv[14],
                            "montoNetoActivoFijo"        => $vvv[15],
                            "ivaActivoFijo"              => $vvv[16],
                            "ivaUsoComun"                => $vvv[17],
                            "impuestoSinDerechoCredito"  => $vvv[18],
                            "ivaNoRetenido"              => $vvv[19],
                            "tabacosPuros"               => $vvv[20],
                            "tabacosCigarrillos"         => $vvv[21],
                            "tabacosElaborados"          => $vvv[22],
                            "otrosImpuestos"             => [[
                                "codigoOtroImpuesto" => $vvv[24],
                                "valorOtroImpuesto"  => $vvv[25],
                                "tasaOtroImpuesto"   => $vvv[26],
                            ]],
                        ];
                    }
                }

                if ($operacion === "VENTA") {
                    $details[] = [
                        "tipoDTE"              => $vvv[1],
                        "tipoCompra"           => $vvv[2],
                        "rutCliente"           => $vvv[3],
                        "razonSocial"          => $vvv[4],
                        "folio"                => $vvv[5],
                        "fechaEmision"         => $vvv[6],
                        "fechaRecepcion"       => $vvv[7],
                        "montoExento"          => $vvv[10],
                        "montoNeto"            => $vvv[11],
                        "montoIvaRecuperable"  => $vvv[12],
                        "montoTotal"           => $vvv[13],
                        "ivaNoRetenido"        => $vvv[16],
                        "valorOtroImpuesto"    => $vvv[count($vvv) - 2],
                        "tasaOtroImpuesto"     => $vvv[count($vvv) - 1],
                    ];
                }
            }
        }

        return $details;
    }

    public function summary(string $rut, string $dv, ?string $day, string $month, string $year, string $status, string $operation, mixed $detail): array
    {
        $ptributario  = $year . $month;
        $estadoContab = $status;
        $operacion    = $operation;

        $body = json_encode([
            "metaData" => [
                "namespace"      => "cl.sii.sdi.lob.diii.consdcv.data.api.interfaces.FacadeService/getResumenExport",
                "conversationId" => $this->session_data['TOKEN'],
                "transactionId"  => "0c94e85a-4304-4b82-b661-487aecefc77d",
                "page"           => null,
            ],
            "data" => [
                "rutEmisor"    => $this->session_data['NETSCAPE_LIVEWIRE_rut'],
                "dvEmisor"     => $this->session_data['NETSCAPE_LIVEWIRE_dv'],
                "ptributario"  => $ptributario,
                "estadoContab" => $estadoContab,
                "operacion"    => $operacion,
            ],
        ]);

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'https://www4.sii.cl/consdcvinternetui/services/data/facadeService/getResumenExport');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        curl_setopt($ch, CURLOPT_ENCODING, 'gzip, deflate');
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $this->buildHeaders());

        $result    = curl_exec($ch);
        $curlError = curl_errno($ch) ? curl_error($ch) : null;
        curl_close($ch);

        if ($curlError) {
            throw new \RuntimeException('cURL error en summary(): ' . $curlError);
        }

        $data = json_decode($result, true);

        if (!is_array($data) || !isset($data['data']) || !is_array($data['data'])) {
            throw new \RuntimeException(
                'Respuesta inesperada del SII en summary(). Posible sesión expirada o servicio no disponible.'
            );
        }

        $summaries = [];

        foreach ($data['data'] as $k => $dd) {
            if ($k === 0) continue;

            foreach (explode("\n", $dd) as $ddd) {
                $vvv = explode(";", $ddd);

                if ($operacion === "COMPRA") {
                    $summaries[] = [
                        "tipoDteString"    => $vvv[0],
                        "totalDocumentos"  => $vvv[1],
                        "montoExento"      => $vvv[2],
                        "montoNeto"        => $vvv[3],
                        "ivaRecuperable"   => $vvv[4],
                        "ivaUsoComun"      => $vvv[5],
                        "ivaNoRecuperable" => $vvv[6],
                        "montoTotal"       => $vvv[7],
                    ];
                }

                if ($operacion === "VENTA") {
                    $summaries[] = [
                        "tipoDteString"   => $vvv[0],
                        "totalDocumentos" => $vvv[1],
                        "montoExento"     => $vvv[2],
                        "montoNeto"       => $vvv[3],
                        "montoIva"        => $vvv[4],
                        "montoTotal"      => $vvv[5],
                    ];
                }
            }
        }

        $details = $detail ? $this->details($ptributario, $estadoContab, $operation) : [];

        $months = ["---", "Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio",
                   "Julio", "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre"];

        $info = [
            "rutEmpresa" => $rut . "-" . $dv,
            "nombreMes"  => $months[intval($month)],
            "mes"        => $month,
            "anio"       => $year,
            "dia"        => $day,
            "periodo"    => $year . $month,
            "fecha"      => $year . "-" . $month . "-" . $day . "T00:00:00",
        ];

        if ($operacion === "VENTA") {
            return [
                "caratula" => $info,
                "ventas"   => ["resumenes" => $summaries, "detalleVentas" => $details],
            ];
        }

        if ($operacion === "COMPRA") {
            return [
                "caratula" => $info,
                "compras"  => ["resumenes" => $summaries, "detalleCompras" => $details],
            ];
        }

        throw new \InvalidArgumentException('Operación inválida: ' . $operacion . '. Use "COMPRA" o "VENTA".');
    }

    private function buildHeaders(): array
    {
        $s = $this->session_data;

        return [
            'Accept: application/json, text/plain, */*',
            'Accept-Language: es-419,es;q=0.9',
            'Cache-Control: no-cache',
            'Connection: keep-alive',
            'Content-Type: application/json',
            'Cookie: s_cc=true'
                . '; NETSCAPE_LIVEWIRE.rut='  . $s['NETSCAPE_LIVEWIRE_rut']
                . '; NETSCAPE_LIVEWIRE.rutm=' . $s['NETSCAPE_LIVEWIRE_rutm']
                . '; NETSCAPE_LIVEWIRE.dv='   . $s['NETSCAPE_LIVEWIRE_dv']
                . '; NETSCAPE_LIVEWIRE.dvm='  . $s['NETSCAPE_LIVEWIRE_dvm']
                . '; NETSCAPE_LIVEWIRE.clave='. $s['NETSCAPE_LIVEWIRE_clave']
                . '; NETSCAPE_LIVEWIRE.sec='  . $s['NETSCAPE_LIVEWIRE_sec']
                . '; NETSCAPE_LIVEWIRE.lms='  . $s['NETSCAPE_LIVEWIRE_lms']
                . '; s_sq=%5B%5BB%5D%5D'
                . '; NETSCAPE_LIVEWIRE.mac='  . $s['NETSCAPE_LIVEWIRE_mac']
                . '; NETSCAPE_LIVEWIRE.exp='  . $s['NETSCAPE_LIVEWIRE_exp']
                . '; TOKEN='                  . $s['TOKEN']
                . '; CSESSIONID='             . $s['CSESSIONID'],
            'Origin: https://www4.sii.cl',
            'Pragma: no-cache',
            'Referer: https://www4.sii.cl/consdcvinternetui/',
            'Sec-Fetch-Dest: empty',
            'Sec-Fetch-Mode: cors',
            'Sec-Fetch-Site: same-origin',
            'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 OPR/96.0.0.0',
        ];
    }
}
