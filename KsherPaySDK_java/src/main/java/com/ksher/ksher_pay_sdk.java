package com.ksher;

import com.alibaba.fastjson.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;

import java.security.Signature;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.*;

/***
 * ksher 生存的RSA私钥是pkcs1格式，即-----BEGIN RSA PRIVATE KEY----- 开头的。java需要pkcs8格式的，
 * 是以-----BEGIN PRIVATE KEY-----开通的，以下命令可以装有openssl环境的linux机器上转化pcks1到pcks8格式。
 * 需要pkcs8格式的可以调用命令行转换:
 * openssl pkcs8 -topk8 -inform PEM -in private.key -outform pem -nocrypt -out pkcs8.pem
 * 1、PKCS1私钥生成
 * openssl genrsa -out private.pem 1024
 * 2、PKCS1私钥转换为PKCS8(该格式一般Java调用)
 * openssl pkcs8 -topk8 -inform PEM -in private.pem -outform pem -nocrypt -out pkcs8.pem
 */
public class ksher_pay_sdk {

    private String appid;
    private String privateKey;
    //PayDomain    =  "https://api.mch.ksher.net/KsherPay"
    private String PayDomain = "http://ht.dspread.com/front/KsherPay";
    //定义加密方式
    private final String KEY_RSA = "RSA";
    //定义签名算法
    private final String KEY_RSA_SIGNATURE = "MD5withRSA";
    private final java.text.SimpleDateFormat timeStampFormat = new java.text.SimpleDateFormat("yyyyMMddHHmmss");
    private final String publicKey = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL7955OCuN4I8eYNL/mixZWIXIgCvIVEivlxqdpiHPcOLdQ2RPSx/pORpsUu/E9wz0mYS2PY7hNc2mBgBOQT+wUCAwEAAQ==";

    public ksher_pay_sdk(String appid, String privateKey) {
        this.appid = appid;
        this.privateKey = privateKey;
    }

    /**
     * sign byte to hex
     * @param bytes
     * @return
     */
    public String bytesToHex(byte[] bytes) {
        StringBuilder buf = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) { // 使用String的format方法进行转换
            buf.append(String.format("%02x", new Integer(b & 0xff)));
        }
        return buf.toString();
    }

    /**
     * hex string to byte
     * @param sign
     * @return
     */
    public byte[] unHexVerify(String sign) {
        int length = sign.length();
        byte[] result = new byte[length / 2];
        for (int i = 0; i < length; i += 2)
            result[i / 2] = (byte) ((Character.digit(sign.charAt(i), 16) << 4) + Character.digit(sign.charAt(i + 1), 16));
        return result;
    }

    /**
     * 请求参数排序
     * @param params
     * @return
     */
    public byte[] getParamsSort(Map params)
    {
        java.util.TreeMap<String, String> sortParas = new java.util.TreeMap<String, String>();
        sortParas.putAll(params);
        java.util.Iterator<String> it = sortParas.keySet().iterator();
        StringBuilder encryptedStr = new StringBuilder();
        while (it.hasNext()) {
            String key = it.next();
            encryptedStr.append(key).append("=").append(params.get(key));
        }
        return encryptedStr.toString().getBytes();
    }

    /**
     * 签名
     * @param params
     * @return
     */
    public String KsherSign(Map params) throws Exception {
        //将私钥加密数据字符串转换为字节数组
        byte[] data = getParamsSort(params);
        // 解密由base64编码的私钥
        byte[] privateKeyBytes = Base64.decodeBase64(this.privateKey.getBytes());
        // 构造PKCS8EncodedKeySpec对象
        PKCS8EncodedKeySpec pkcs = new PKCS8EncodedKeySpec(privateKeyBytes);
        // 指定的加密算法
        KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
        // 取私钥对象
        PrivateKey key = factory.generatePrivate(pkcs);
        // 用私钥对信息生成数字签名
        Signature signature = Signature.getInstance(KEY_RSA_SIGNATURE);
        signature.initSign(key);
        signature.update(data);
        byte[] sign_byte = signature.sign();
        //String sing_str = new String(Base64.encodeBase64(signature.sign()));
        return bytesToHex(sign_byte);
    }
    /**
     * 校验数字签名
     * @param data
     * @param sign
     * @return 校验成功返回true，失败返回false
     */
    public boolean KsherVerify(Map data, String sign) throws Exception {
        boolean flag = false;
        //将私钥加密数据字符串转换为字节数组
        byte[] dataByte = getParamsSort(data);
        // 解密由base64编码的公钥
        byte[] publicKeyBytes = Base64.decodeBase64(publicKey.getBytes());
        // 构造X509EncodedKeySpec对象
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        // 指定的加密算法
        KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
        // 取公钥对象
        PublicKey key = factory.generatePublic(keySpec);
        // 用公钥验证数字签名
        Signature signature = Signature.getInstance(KEY_RSA_SIGNATURE);
        signature.initVerify(key);
        signature.update(dataByte);
        return signature.verify(unHexVerify(sign));
    }

    /**
     * post请求(用于key-value格式的参数)
     *
     * @param url
     * @param params
     * @return
     */
    public String KsherPost(String url, Map params) throws Exception {
        HttpClient client = new DefaultHttpClient();
        HttpPost post = new HttpPost(PayDomain + url);
        //设置公共参数
        params.put("appid", this.appid);
        params.put("nonce_str", RandomStringUtils.randomAlphanumeric(4));
        params.put("time_stamp", timeStampFormat.format(new java.util.Date()));

        List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
        for (Iterator iter = params.keySet().iterator(); iter.hasNext(); ) {
            String name = (String) iter.next();
            String value = String.valueOf(params.get(name));
            urlParameters.add(new BasicNameValuePair(name, value));
        }
        String sign = KsherSign(params);
        urlParameters.add(new BasicNameValuePair("sign", sign));
        post.setEntity(new UrlEncodedFormEntity(urlParameters));
        HttpResponse response = client.execute(post);
        BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
        StringBuffer result = new StringBuffer();
        String line = "";
        while ((line = rd.readLine()) != null) {
            result.append(line);
        }
        rd.close();
        System.out.println(result.toString());

        JSONObject json = JSONObject.parseObject(result.toString());
        boolean isVerify = KsherVerify(json.getJSONObject("data"), json.getString("sign"));
        if(isVerify){
            return result.toString();
        }else{
            throw new Exception("verify signature failed");
        }
    }

    /**
     * 商户扫用户(B扫C)
     * @param mchOrderNo 商户订单号
     * @param feeType 支付币种 'THB'
     * @param authCode 支付条码
     * @param channel 支付通道 wechat aplipay
     * @param operatorId 操作员编号
     * @param totalFee 支付金额
     * @return
     */
    public String QuickPay(String mchOrderNo, String feeType, String authCode, String channel, String operatorId, Integer totalFee) {
        try {
            java.util.Map<String, String> paras = new java.util.HashMap<String, String>();
            paras.put("mch_order_no", mchOrderNo);
            paras.put("total_fee", totalFee.toString());
            paras.put("fee_type", feeType);
            paras.put("auth_code", authCode);
            paras.put("channel", channel);
            paras.put("operator_id", operatorId);
            return KsherPost(PayDomain + "/quick_pay", paras);
        } catch (Exception ex) {
            ex.printStackTrace();
            return ex.getMessage();
        }
    }

    /**
     * C扫B支付
     * 必传参数
     * 	mch_order_no
     * 	total_fee
     * 	fee_type
     * 	channel
     * 选传参数
     * 	redirect_url
     * 	notify_url
     * 	paypage_title
     * 	operator_id
     * @return
     */
    public String JsApiPay(String mchOrderNo,String feeType,String channel,Integer totalFee){
        try {
            java.util.Map<String, String> paras = new java.util.HashMap<String, String>();
            paras.put("mch_order_no", mchOrderNo);
            paras.put("total_fee", totalFee.toString());
            paras.put("fee_type", feeType);
            paras.put("channel", channel);
            return KsherPost(PayDomain + "/jsapi_pay", paras);
        } catch (Exception ex) {
            ex.printStackTrace();
            return ex.getMessage();
        }
    }
    /**
    动态码支付
    :param kwargs:
    必传参数
        mch_order_no
        total_fee
        fee_type
        channel
    选传参数
        redirect_url
        notify_url
        paypage_title
        product
        attach
        operator_id
        device_id
        img_type
    :return:
    **/
    public String NativePay(String mchOrderNo, String feeType, String channel,Integer totalFee) throws Exception {
        java.util.Map<String, String> paras = new java.util.HashMap<String, String>();
        paras.put("mch_order_no", mchOrderNo);
        paras.put("total_fee", totalFee.toString());
        paras.put("fee_type", feeType);
        paras.put("channel", channel);
        return KsherPost(PayDomain + "/native_pay", paras);
    }
    /**
    小程序支付
    :param kwargs:
    必传参数
        mch_order_no
        total_fee
        fee_type
        channel
        sub_openid
        channel_sub_appid
    选传参数
        redirect_url
        notify_url
        paypage_title
        product
        operator_id
    :return:
    **/
    public String MiniproPay(String mchOrderNo, String feeType, String channel, String subOpenid, String channelSubAppId, Integer totalFee) throws Exception{
        java.util.Map<String, String> paras = new java.util.HashMap<String, String>();
        paras.put("mch_order_no", mchOrderNo);
        paras.put("total_fee", totalFee.toString());
        paras.put("fee_type", feeType);
        paras.put("channel", channel);
        paras.put("sub_openid", subOpenid);
        paras.put("channel_sub_appid", channelSubAppId);
        return KsherPost(PayDomain + "/mini_program_pay", paras);
    }
    /**
    app支付
    :param kwargs:
    必传参数
        mch_order_no
        total_fee
        fee_type
        channel
        sub_openid
        channel_sub_appid
    选传参数
        redirect_url
        notify_url
        paypage_title
        product
        attach
        operator_id
        refer_url 仅当channel为alipay时需要
    :return:
    **/
    public String AppPay(String mchOrderNo,String feeType,String channel,String subOpenid,String channelSubAppId, Integer totalFee) throws Exception {
        java.util.Map<String, String> paras = new java.util.HashMap<String, String>();
        paras.put("mch_order_no", mchOrderNo);
        paras.put("total_fee", totalFee.toString());
        paras.put("fee_type", feeType);
        paras.put("channel", channel);
        paras.put("sub_openid", subOpenid);
        paras.put("channel_sub_appid", channelSubAppId);
        return KsherPost(PayDomain + "/app_pay", paras);
    }
    /**
    H5支付，仅支持channel=alipay
    :param kwargs:
    必传参数
        mch_order_no
        total_fee
        fee_type
        channel
    选传参数
        redirect_url
        notify_url
        paypage_title
        product
        attach
        operator_id
        device_id
        refer_url
    :return:
    **/
    public String WapPay(String mchOrderNo,String feeType,String channel, Integer totalFee) throws Exception {
        java.util.Map<String, String> paras = new java.util.HashMap<String, String>();
        paras.put("mch_order_no", mchOrderNo);
        paras.put("total_fee", totalFee.toString());
        paras.put("fee_type", feeType);
        paras.put("channel", channel);
        return KsherPost(PayDomain + "/wap_pay", paras);
    }
    /**
    PC网站支付，仅支持channel=alipay
    :param kwargs:
    必传参数
        mch_order_no
        total_fee
        fee_type
        channel
    选传参数
        redirect_url
        notify_url
        paypage_title
        product
        attach
        operator_id
        device_id
        refer_url
    :return:
    **/
    public String WepPay(String mchOrderNo,String feeType,String channel,Integer totalFee)throws Exception{
        java.util.Map<String, String> paras = new java.util.HashMap<String, String>();
        paras.put("mch_order_no", mchOrderNo);
        paras.put("total_fee", totalFee.toString());
        paras.put("fee_type", feeType);
        paras.put("channel", channel);
        return KsherPost(PayDomain + "/wap_pay", paras);
    }
    /**
    订单查询
    :param kwargs:
    必传参数
        mch_order_no、ksher_order_no、channel_order_no三选一
    :return:
    **/
    public String OrderQuery(String mchOrderNo) throws Exception{
        java.util.Map<String, String> paras = new java.util.HashMap<String, String>();
        paras.put("mch_order_no", mchOrderNo);
        return KsherPost(PayDomain + "/order_query", paras);
    }
    /**
    订单关闭
    :param kwargs:
    必传参数
        mch_order_no、ksher_order_no、channel_order_no三选一
    选传参数
        operator_id
    :return:
    **/
    public String OrderClose(String mchOrderNo) throws Exception {
        java.util.Map<String, String> paras = new java.util.HashMap<String, String>();
        paras.put("mch_order_no", mchOrderNo);
        return KsherPost(PayDomain + "/order_close", paras);
    }
    /**
    订单撤销
    :param kwargs:
    必传参数
        mch_order_no、ksher_order_no、channel_order_no三选一
    选传参数
        operator_id
    :return:
    **/
    public String OrderReverse(String mchOrderNo) throws Exception{
        java.util.Map<String, String> paras = new java.util.HashMap<String, String>();
        paras.put("mch_order_no", mchOrderNo);
        return KsherPost(PayDomain + "/order_reverse", paras);
    }
    /**
    订单退款
    :param kwargs:
    必传参数
        total_fee
        fee_type
        refund_fee
        mch_refund_no
        mch_order_no、ksher_order_no、channel_order_no三选一
    选传参数
        operator_id
    :return:
    **/
    public String OrderRefund(String mchRefundNo,String feeType,String mchOrderNo,Integer refundFee,Integer totalFee) throws Exception {
        java.util.Map<String, String> paras = new java.util.HashMap<String, String>();
        paras.put("mch_refund_no", mchRefundNo);
        paras.put("fee_type", feeType);
        paras.put("mchOrderNo", mchOrderNo);
        paras.put("refund_fee", refundFee.toString());
        paras.put("total_fee", totalFee.toString());
        return KsherPost(PayDomain + "/order_refund", paras);
    }
    /**
    退款查询
    :param kwargs:
        必传参数
            mch_refund_no、ksher_refund_no、channel_refund_no三选一
            mch_order_no、ksher_order_no、channel_order_no三选一
    **/
    public String RefundQuery(String mchRefundNo, String mchOrderNo) throws Exception{
        java.util.Map<String, String> paras = new java.util.HashMap<String, String>();
        paras.put("mch_refund_no", mchRefundNo);
        paras.put("mchOrderNo", mchOrderNo);
        return KsherPost(PayDomain + "/refund_query", paras);
    }
    /**
    汇率查询
    :param kwargs:
        必传参数
        channel
        fee_type
        date
    :return:
    **/
    public String RateQuery(String channel, String feeType,String  date) throws Exception{
        java.util.Map<String, String> paras = new java.util.HashMap<String, String>();
        paras.put("channel", channel);
        paras.put("fee_type", feeType);
        paras.put("date", date);
        return KsherPost(PayDomain + "/rate_query", paras);
    }
}