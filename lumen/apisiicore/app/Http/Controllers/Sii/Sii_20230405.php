<?php

namespace App\Http\Controllers\Sii;


class Sii
{
    var $user;
    var $password;
    var $session_data;
    function __construct($user, $pass)
    {
        $this->user = $user;
        $this->password = $pass;
        $this->login($user, $pass);
    }
    public function login($user, $pass)
    {
        $curl = curl_init();
        $rr = explode("-", $user);
        $rut = $rr[0];
        $dv =  $rr[1];
        $rutcntr = str_replace(",", ".", number_format($rut)) . "-" . $dv;

        //$pass = "bring76";
        curl_setopt_array($curl, array(
            CURLOPT_URL => 'https://zeusr.sii.cl/cgi_AUT2000/CAutInicio.cgi',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 0,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_COOKIESESSION => true,
            CURLOPT_HEADER => 1,
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_POSTFIELDS => 'rut=' . $rut . '&dv=' . $dv . '&referencia=https%3A%2F%2Fmisiir.sii.cl%2Fcgi_misii%2Fsiihome.cgi&411=&rutcntr=' . $rutcntr . '&clave=' . $pass,
            CURLOPT_HTTPHEADER => array(
                'Content-Type: application/x-www-form-urlencoded'
            ),
        ));
        $response = curl_exec($curl);
        preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $response, $matches);        // get cookie
        $cookies = array();
        foreach ($matches[1] as $item) {
            parse_str($item, $cookie);
            $cookies = array_merge($cookies, $cookie);
        }
        curl_close($curl);
        $this->session_data = $cookies;
    }
    public function details($ptributario,$estadoContab,$operacion)
    {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, 'https://www4.sii.cl/consdcvinternetui/services/data/facadeService/getDetalleCompraExport');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, "{\"metaData\":{\"namespace\":\"cl.sii.sdi.lob.diii.consdcv.data.api.interfaces.FacadeService/getDetalleCompraExport\",\"conversationId\":\"" . $this->session_data['TOKEN'] . "\",\"transactionId\":\"568ed82b-1a07-45ec-93ef-0d1c7466fb3c\",\"page\":null},\"data\":{\"rutEmisor\":\"" . $this->session_data['NETSCAPE_LIVEWIRE_rut'] . "\",\"dvEmisor\":\"" . $this->session_data['NETSCAPE_LIVEWIRE_dv'] . "\",\"ptributario\":\"" . $ptributario . "\",\"codTipoDoc\":0,\"operacion\":\"" . $operacion . "\",\"estadoContab\":\"" . $estadoContab . "\"}}");
        curl_setopt($ch, CURLOPT_ENCODING, 'gzip, deflate');

        $headers = array();
        $headers[] = 'Accept: application/json, text/plain, */*';
        $headers[] = 'Accept-Language: es-419,es;q=0.9';
        $headers[] = 'Cache-Control: no-cache';
        $headers[] = 'Connection: keep-alive';
        $headers[] = 'Content-Type: application/json';
        $headers[] = 'Cookie: s_cc=true; NETSCAPE_LIVEWIRE.rut=' . $this->session_data['NETSCAPE_LIVEWIRE_rut'] . '; NETSCAPE_LIVEWIRE.rutm=' . $this->session_data['NETSCAPE_LIVEWIRE_rutm'] . '; NETSCAPE_LIVEWIRE.dv=' . $this->session_data['NETSCAPE_LIVEWIRE_dv'] . '; NETSCAPE_LIVEWIRE.dvm=' . $this->session_data['NETSCAPE_LIVEWIRE_dvm'] . '; NETSCAPE_LIVEWIRE.clave=' . $this->session_data['NETSCAPE_LIVEWIRE_clave'] . '; NETSCAPE_LIVEWIRE.sec=' . $this->session_data['NETSCAPE_LIVEWIRE_sec'] . '; NETSCAPE_LIVEWIRE.lms=' . $this->session_data['NETSCAPE_LIVEWIRE_lms'] . '; s_sq=%5B%5BB%5D%5D; NETSCAPE_LIVEWIRE.mac=' . $this->session_data['NETSCAPE_LIVEWIRE_mac'] . '; NETSCAPE_LIVEWIRE.exp=' . $this->session_data['NETSCAPE_LIVEWIRE_exp'] . '; TOKEN=' . $this->session_data['TOKEN'] . '; CSESSIONID=' . $this->session_data['CSESSIONID'];
        $headers[] = 'Origin: https://www4.sii.cl';
        $headers[] = 'Pragma: no-cache';
        $headers[] = 'Referer: https://www4.sii.cl/consdcvinternetui/';
        $headers[] = 'Sec-Fetch-Dest: empty';
        $headers[] = 'Sec-Fetch-Mode: cors';
        $headers[] = 'Sec-Fetch-Site: same-origin';
        $headers[] = 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 OPR/96.0.0.0';
        $headers[] = 'Sec-Ch-Ua: \"Not=A?Brand\";v=\"8\", \"Chromium\";v=\"110\", \"Opera\";v=\"96\"';
        $headers[] = 'Sec-Ch-Ua-Mobile: ?0';
        $headers[] = 'Sec-Ch-Ua-Platform: \"macOS\"';
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        $result = curl_exec($ch);
        if (curl_errno($ch)) {
            echo 'Error:' . curl_error($ch);
        }
        curl_close($ch);
        $data = (json_decode($result, true));
        $v = $data['data'];
        $summaries = [];
        $details = [];
        foreach ($v as $k => $dd) {
            if ($k > 0) {
                $vv = explode("\n", $dd);
                foreach ($vv as $kk => $ddd) {
                    $vvv = explode(";", $ddd);
                    if ($operacion == "COMPRA") {
                        //$details[] = $vvv;
                        if($vvv[0] == ''){
                            $details[count($details)-1]['otrosImpuestos'][] = [
                                "codigoOtroImpuesto"     => $vvv[24],
                                "valorOtroImpuesto" => $vvv[25],
                                "tasaOtroImpuesto" => $vvv[26],
                            ];
                        }
                        else{
                            $details[] = [
                                "tipoDTE"     => $vvv[1],
                                "tipoCompra"     => $vvv[2],
                                "rutProveedor"     => $vvv[3],
                                "razonSocial"     => $vvv[4],
                                "folio"     => $vvv[5],
                                "fechaEmision"     => $vvv[6],
                                "fechaRecepcion"     => $vvv[7],
                                "montoExento"     => $vvv[9],
                                "montoNeto"     => $vvv[10],
                                "montoIvaRecuperable"     => $vvv[11],
                                "montoIvaNoRecuperable"     => $vvv[12],
                                "codigoIvaNoRecuperable"     => $vvv[13],
                                "montoTotal"     => $vvv[14],
                                "montoNetoActivoFijo"     => $vvv[15],
                                "ivaActivoFijo"     => $vvv[16],
                                "ivaUsoComun"     => $vvv[17],
                                "impuestoSinDerechoCredito"     => $vvv[18],
                                "ivaNoRetenido"     => $vvv[19],
                                "tabacosPuros" => $vvv[20],
                                "tabacosCigarrillos" => $vvv[21],
                                "tabacosElaborados"  => $vvv[22],
                                "otrosImpuestos"=>[
                                    [
                                        "codigoOtroImpuesto"     => $vvv[24],
                                        "valorOtroImpuesto" => $vvv[25],
                                        "tasaOtroImpuesto" => $vvv[26],
                                    ]
                                ]
                            ];
                        }

                    }
                    if ($operacion == "VENTA") {
                        $details[] = [
                            "tipoDTE" => $vvv[1],
                            "tipoCompra" => $vvv[2],
                            "rutCliente" => $vvv[3],
                            "razonSocial" => $vvv[4],
                            "folio"     => $vvv[5],
                            "fechaEmision"     => $vvv[6],
                            "fechaRecepcion"     => $vvv[7],
                            //.Fecha de acuse
                            //.Fecha de reclamacion
                            "montoExento"     => $vvv[10],
                            "montoNeto"     => $vvv[11],
                            "montoIvaRecuperable" => $vvv[12],
                            "montoTotal"     => $vvv[13],
                            //.iva retenido total
                            //.iva retenido parcial
                            "ivaNoRetenido"     => $vvv[16],
                            //.iva propio
                            //.iva terceros
                            //.RUT Emisor Liquid. Factura
                            //.Neto Comision Liquid. Factura    
                            //.Exento Comision Liquid. Factura
                            //.IVA Comision Liquid. Factura
                            //.IVA fuera de plazo
                            //.Tipo Docto. Referencia
                            //.Folio Docto. Referencia
                            //.Num. Ident. Receptor Extranjero
                            //.Nacionalidad Receptor Extranjero
                            //.Credito empresa constructora
                            //.Impto. Zona Franca (Ley 18211)
                            //.Garantia Dep. Envases
                            //.Indicador Venta sin Costo
                            //.Indicador Servicio Periodico
                            //.Monto No facturable
                            //.Total Monto Periodo
                            //.Venta Pasajes Transporte Nacional
                            //.Venta Pasajes Transporte Internacional
                            //.Numero Interno
                            //.Codigo Sucursal
                            //.NCE o NDE sobre Fact. de Compra
                            //.Codigo Otro Imp.
                            //.Codigo Otro Imp.
                            "valorOtroImpuesto" => $vvv[count($vvv)-2],
                            "tasaOtroImpuesto" => $vvv[count($vvv)-1],
                        ];
                    }
                }
            }
            /*
            if($detail){
                $di = $this->details($dd['rsmnTipoDocInteger'],$rut,$dv,$day,$month,$year,$status,$operation);
                $details = [];
                foreach($di as $kk=>$vv){
                    //$details[] = $vv;
                    $otherTaxes = 0;
                    $statusAcuse = 0;
                    $details[] = [
                        "tipoDTEString" => $dd['dcvNombreTipoDoc'],
                        "tipoDTE" => $dd['rsmnTipoDocInteger'],
                        "tipoCompra" => $vv['descTipoTransaccion'],
                        "rutCliente" => $vv['detRutDoc']."-".$vv['detDvDoc'],
                        "razonSocial" => $vv['detRznSoc'],
                        "folio" => $vv['detNroDoc'],
                        "fechaEmision" => $vv['detFchDoc'],
                        "fechaRecepcion" => $vv['detFecRecepcion'],
                        "acuseRecibo" => "Forma de pago Contado",
                        "estadoAcuse" => $statusAcuse,
                        "montoExento" => $vv['detMntExe'],
                        "montoNeto" => $vv['detMntNeto'],
                        "montoIvaRecuperable" => $vv['detMntIVA'],
                        "montoTotal" => $vv['detMntTotal'],
                        "ivaNoRetenido" => $vv['detIVANoRetenido'],
                        "totalOtrosImpuestos" => $otherTaxes,
                        "valorOtroImpuesto" => null,
                        "tasaOtroImpuesto" => null,
                        "tipoDocReferencia" => $dd['rsmnTipoDocInteger'],
                        "referencias" => [],
                        "referenciado" => [],
                        "reparos" => [],
                        "otrosImpuestos" => [],
                        "estado" => "--",// "Confirmada"
                    ];
                }
            }*/
        }
        return $details;
    }
    public function summary($rut, $dv, $day, $month, $year, $status, $operation, $detail)
    {
        $rutEmisor = $rut;
        $dvEmisor = $dv;
        $ptributario = $year . $month;
        $estadoContab = $status;
        $operacion = $operation;
        $busquedaInicial = true;
        $trasaction = "25f88e86-810a-4464-9b3a-8440486602b4";
        $dtCookie = "v_4_srv_40_sn_C9B3CB578B663E79852E2F0B8C94CFA9_perc_100000_ol_0_mul_1_app-3Aea7c4b59f27d43eb_0_app-3Ab23bdcbbe9c1ae0d_0";
        $s_sq = "%5B%5BB%5D%5D";
        $summaries = [];
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, 'https://www4.sii.cl/consdcvinternetui/services/data/facadeService/getResumenExport');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, "{\"metaData\":{\"namespace\":\"cl.sii.sdi.lob.diii.consdcv.data.api.interfaces.FacadeService/getResumenExport\",\"conversationId\":\"".$this->session_data['TOKEN']."\",\"transactionId\":\"0c94e85a-4304-4b82-b661-487aecefc77d\",\"page\":null},\"data\":{\"rutEmisor\":\"".$this->session_data['NETSCAPE_LIVEWIRE_rut']."\",\"dvEmisor\":\"".$this->session_data['NETSCAPE_LIVEWIRE_dv']."\",\"ptributario\":\"".$ptributario."\",\"estadoContab\":\"".$estadoContab."\",\"operacion\":\"".$operacion."\"}}");
        curl_setopt($ch, CURLOPT_ENCODING, 'gzip, deflate');

        $headers = array();
        $headers[] = 'Accept: application/json, text/plain, */*';
        $headers[] = 'Accept-Language: es-419,es;q=0.9';
        $headers[] = 'Cache-Control: no-cache';
        $headers[] = 'Connection: keep-alive';
        $headers[] = 'Content-Type: application/json';
        $headers[] = 'Cookie: s_cc=true; NETSCAPE_LIVEWIRE.rut='.$this->session_data['NETSCAPE_LIVEWIRE_rut'].'; NETSCAPE_LIVEWIRE.rutm='.$this->session_data['NETSCAPE_LIVEWIRE_rut'].'; NETSCAPE_LIVEWIRE.dv='.$this->session_data['NETSCAPE_LIVEWIRE_dv'].'; NETSCAPE_LIVEWIRE.dvm='.$this->session_data['NETSCAPE_LIVEWIRE_dvm'].'; NETSCAPE_LIVEWIRE.clave='.$this->session_data['NETSCAPE_LIVEWIRE_clave'].'; NETSCAPE_LIVEWIRE.sec=0000; NETSCAPE_LIVEWIRE.lms=120; NETSCAPE_LIVEWIRE.mac='.$this->session_data['NETSCAPE_LIVEWIRE_mac'].'; NETSCAPE_LIVEWIRE.exp='.$this->session_data['NETSCAPE_LIVEWIRE_exp'].'; TOKEN='.$this->session_data['TOKEN'].'; CSESSIONID='.$this->session_data['CSESSIONID'].'';
        $headers[] = 'Origin: https://www4.sii.cl';
        $headers[] = 'Pragma: no-cache';
        $headers[] = 'Referer: https://www4.sii.cl/consdcvinternetui/';
        $headers[] = 'Sec-Fetch-Dest: empty';
        $headers[] = 'Sec-Fetch-Mode: cors';
        $headers[] = 'Sec-Fetch-Site: same-origin';
        $headers[] = 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 OPR/96.0.0.0';
        $headers[] = 'Sec-Ch-Ua: \"Not=A?Brand\";v=\"8\", \"Chromium\";v=\"110\", \"Opera\";v=\"96\"';
        $headers[] = 'Sec-Ch-Ua-Mobile: ?0';
        $headers[] = 'Sec-Ch-Ua-Platform: \"macOS\"';
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

        $result = curl_exec($ch);
        $data = (json_decode($result, true));
        $v = $data['data'];
        foreach($v as $k=>$dd){
            if($k >0 ){
                $vv = explode("\n",$dd);
                foreach($vv as $kk=>$ddd){
                    $vvv = explode(";",$ddd);
                    if($operacion == "COMPRA"){
                        $summaries[] =[
                            //"tipoDte" => $vvv[0],
                            "tipoDteString" => $vvv[0],
                            "totalDocumentos" => $vvv[1],
                            "montoExento" => $vvv[2],
                            "montoNeto" => $vvv[3],
                            "ivaRecuperable" => $vvv[4],
                            "ivaUsoComun" => $vvv[5],
                            "ivaNoRecuperable" => $vvv[6],
                            "montoTotal" => $vvv[7],
                            //"estado" =>$vvv[0],
                        ];
                    }

                    if($operacion == "VENTA"){
                        $summaries[] =[
                            //"tipoDte" => $vvv[0],
                            "tipoDteString" => $vvv[0],
                            "totalDocumentos" => $vvv[1],
                            "montoExento" => $vvv[2],
                            "montoNeto" => $vvv[3],
                            "montoIva" => $vvv[4],
                            "montoTotal" => $vvv[5],
                            //"estado" =>$vvv[0],
                        ];
                    }
                    /*
                    $summaries[] = [
                    "tipoDte" => $dd['rsmnTipoDocInteger'],
                    "tipoDteString" => $dd['dcvNombreTipoDoc'],
                    "totalDocumentos" => $dd['rsmnTotDoc'],
                    "montoExento" => $dd['rsmnMntExe'],
                    "montoNeto" => $dd['rsmnMntNeto'],
                    "ivaRecuperable" => $dd['rsmnMntIVA'],
                    "ivaUsoComun" => $dd['rsmnIVAUsoComun'],
                    "ivaNoRecuperable" => $dd['rsmnMntIVANoRec'],
                    "montoTotal" => $dd['rsmnMntTotal'],
                    "estado" => $dd['rsmnEstadoContab']
                ];
                    */
                }
            }
        }
        if (curl_errno($ch)) {
            echo 'Error:' . curl_error($ch);
        }
        curl_close($ch);
        $details = $this->details($ptributario,$estadoContab,$operation);
        $months = [
            "---",
            "Enero",
            "Febrero",
            "Marzo",
            "Abril",
            "Mayo",
            "Junio",
            "Julio",
            "Agosto",
            "Septiembre",
            "Octubre",
            "Noviembre",
            "Diciembre"
        ];
        $info = [
            "rutEmpresa" => $rutEmisor . "-" . $dvEmisor,
            "nombreMes" => $months[intval($month)],
            "mes" => $month,
            "anio" => $year,
            "dia" => $day,
            "periodo" => $year . $month,
            "fecha" => $year . "-" . $month . "-" . $day . "T00:00:00"
        ];
        if ($operacion == "VENTA") {
            $d = [
                "caratula" => $info,
                "ventas" => [
                    "resumenes" => $summaries,
                    "detalleVentas" => $details
                ]
            ];
        }
        if ($operacion == "COMPRA") {
            $d = [
                "caratula" => $info,
                "compras" => [
                    "resumenes" => $summaries,
                    "detalleCompras" => $details
                ]
            ];
        }

        return $d;
    }
}


/*

        $ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_USERAGENT,'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/32.0.1700.107 Chrome/32.0.1700.107 Safari/537.36');
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, "{\"metaData\":{\"namespace\":\"cl.sii.sdi.lob.diii.consdcv.data.api.interfaces.FacadeService/getResumen\",\"conversationId\":\"ZXNWZR3RQKKKC\",\"transactionId\":\"224b95cb-640e-465c-8120-4ce338403c6a\",\"page\":null},\"data\":{\"rutEmisor\":\"76897046\",\"dvEmisor\":\"7\",\"ptributario\":\"202303\",\"estadoContab\":\"REGISTRO\",\"operacion\":\"COMPRA\",\"busquedaInicial\":true}}");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_COOKIESESSION, true);
curl_setopt($ch, CURLOPT_COOKIEJAR, 'cookie-name');  //could be empty, but cause problems on some hosts
curl_setopt($ch, CURLOPT_COOKIEFILE, '/var/www/ip4.x/file/tmp');  //could be empty, but cause problems on some hosts
$answer = curl_exec($ch);
if (curl_error($ch)) {
    echo curl_error($ch);
}

//another request preserving the session

curl_setopt($ch, CURLOPT_URL, 'http://www.example.com/profile');
curl_setopt($ch, CURLOPT_POST, false);
curl_setopt($ch, CURLOPT_POSTFIELDS, "");
$answer = curl_exec($ch);
if (curl_error($ch)) {
    echo curl_error($ch);
}*/
        /*fetch("https://www4.sii.cl/consdcvinternetui/services/data/facadeService/getResumen", {
            "headers": {
              "accept": "application/json, text/plain, ",
              "accept-language": "es-419,es;q=0.9",
              "cache-control": "no-cache",
              "content-type": "application/json",
              "pragma": "no-cache",
              "sec-ch-ua": "\"Not=A?Brand\";v=\"8\", \"Chromium\";v=\"110\", \"Opera\";v=\"96\"",
              "sec-ch-ua-mobile": "?0",
              "sec-ch-ua-platform": "\"macOS\"",
              "sec-fetch-dest": "empty",
              "sec-fetch-mode": "cors",
              "sec-fetch-site": "same-origin",
              "x-dtpc": "43$110517245_504h12vKAUDAPCLKPHAAAGSGPLWBNKTBEFCWUNA-0e0"
            },
            "referrer": "https://www4.sii.cl/consdcvinternetui/",
            "referrerPolicy": "no-referrer-when-downgrade",
            "body": "{\"metaData\":{\"namespace\":\"cl.sii.sdi.lob.diii.consdcv.data.api.interfaces.FacadeService/getResumen\",\"conversationId\":\"ZXNWZR3RQKKKC\",\"transactionId\":\"224b95cb-640e-465c-8120-4ce338403c6a\",\"page\":null},\"data\":{\"rutEmisor\":\"76897046\",\"dvEmisor\":\"7\",\"ptributario\":\"202303\",\"estadoContab\":\"REGISTRO\",\"operacion\":\"COMPRA\",\"busquedaInicial\":true}}",
            "method": "POST",
            "mode": "cors",
            "credentials": "include"
          });*/
