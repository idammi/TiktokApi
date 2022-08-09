package com.tt.tiktok;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import com.tt.http.HttpClientFactory;
import com.tt.tiktok.Api.XArgus;
import com.tt.tiktok.Api.XGorgon;
import com.tt.tiktok.Api.XLadon;
import com.tt.tiktok.bean.XArgusSimpleBean;
import com.tt.util.GZipUtil;
import com.tt.util.HexUtil;
import com.tt.util.MDUtil;

import okhttp3.Headers;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class FollowRequest {
	
	public static void main(String[] args) throws IOException {
		String userId = "6707070528605832197";
		String secUserId = "MS4wLjABAAAAJ67QRo2pm1CWuJ552oJ2bFDDjvNgKYOxDAKXtXua1d_BrHHjT8HMBYoxSkeLvM3B";
	
		follow(userId, secUserId);
	}
	
	public static void follow(String userId, String secUserId) throws IOException {
		String url = "https://api16-normal-useast5.us.tiktokv.com/aweme/v1/commit/follow/user/";
		String query = ""
				+ "residence=US&"
				+ "device_id=7074501187519448622&"
				+ "os_version=13.3&"
				+ "iid=7099400845528074030&"
				+ "app_name=musical_ly&"
				+ "locale=en&"
				+ "ac=WIFI&"
				+ "sys_region=US&"
				+ "js_sdk_version=&"
				+ "version_code=24.4.0&"
				+ "channel=App%20Store&"
				+ "op_region=US&"
				+ "tma_jssdk_version=&"
				+ "os_api=18&"
				+ "idfa=9B867BC3-1BEC-4125-A7CB-B9E32D7D969E&"
				+ "idfv=9B867BC3-1BEC-4125-A7CB-B9E32D7D969E&"
				+ "device_platform=iphone&"
				+ "device_type=iPhone8,1&"
				+ "openudid=8786f8333b57720ad8a99d343b1f234236beb3f8&"
				+ "account_region=us&"
				+ "tz_name=US/Eastern&"
				+ "tz_offset=-14400&"
				+ "app_language=en&"
				+ "current_region=US&"
				+ "build_number=244024&"
				+ "aid=1233&"
				+ "mcc_mnc=&"
				+ "screen_width=750&"
				+ "uoo=0&"
				+ "content_language=&"
				+ "language=en&"
				+ "cdid=04640D03-0879-4A80-9479-E4864F9EAE36&"
				+ "app_version=24.4.0";
		
		String body = "channel_id=26&"
				+ "from=0&"
				+ "from_pre=-1&"
				+ "sec_user_id="+secUserId+"&"
				+ "type=1&"
				+ "user_id="+userId;
		
		final String lc_id = "466012054";
		final int sdkver = 0x4030921;
		
		long x_khronos = System.currentTimeMillis()/1000;
		String query_md5_hex = HexUtil.toString(MDUtil.md5(query.getBytes(StandardCharsets.UTF_8)));
		String x_ss_stub = HexUtil.toString(MDUtil.md5(body.getBytes(StandardCharsets.UTF_8))).toUpperCase();
		
		String x_ladon = XLadon.encrypt(x_khronos, lc_id);
		String x_gorgon = XGorgon.build(query_md5_hex, x_ss_stub, sdkver, (int)x_khronos);
		
		XArgusSimpleBean xArgusBean = new XArgusSimpleBean();
//		TODO 填充XArgusSimpleBean对象
		
		String xArgusStr = XArgus.build(xArgusBean);
		
		Headers.Builder headers = new Headers.Builder();
		headers.add("x-tt-token", "04a0a5d6f5f98572df4678ca26d703f98b05967de3eed9786865a36ffba95019231a76f94fa4d7069f95cc572827588b55210c2b57c37ecafb92d2eb999248aae9c2b194c827304a3f1344618ebfeb99b617b46debe21b43ee7e48a98d873c921011c-1.0.1");
		headers.add("x-tt-dm-status", "login=1;ct=1;rt=1");
		headers.add("x-vc-bdturing-sdk-version", "2.2.0");
		headers.add("content-type", "application/x-www-form-urlencoded");
		headers.add("user-agent", "TikTok 24.4.0 rv:244024 (iPhone; iOS 13.3; en_US) Cronet");
		headers.add("x-tt-cmpl-token", "AgQQAPNSF-RPsLJx5wJVIR0i-Ew0aqqyP6zZYMfGEA");
		headers.add("sdk-version", "2");
		headers.add("passport-sdk-version", "5.12.1");
		headers.add("x-ss-stub", x_ss_stub);
		headers.add("x-tt-store-idc", "useast5");
		headers.add("x-tt-store-region", "us");
		headers.add("x-tt-store-region-src", "uid");
		headers.add("x-bd-kmsv", "0");
		headers.add("x-ss-dp", "1233");
		headers.add("x-tt-trace-id", "00-dc64c7fc10622dad59052d062e5804d1-dc64c7fc10622dad-01");
		headers.add("accept-encoding", "gzip, deflate, br");
		headers.add("cookie", "passport_csrf_token=11c5f4255a69d99d8987f045eced0b93");
		headers.add("cookie", "passport_csrf_token_default=11c5f4255a69d99d8987f045eced0b93");
		headers.add("cookie", "cmpl_token=AgQQAPNSF-RPsLJx5wJVIR0i-Ew0aqqyP6zZYMfGgg");
		headers.add("cookie", "multi_sids=7083891346860393499%3Aa0a5d6f5f98572df4678ca26d703f98b");
		headers.add("cookie", "odin_tt=db9af362a4738efb350f4ad0737e32eab4a0584b4250ddc910f541cde772f6229b0cfff7c63de70cb5162ac589701779173356e03e8324e4bc7e3cacf3a77481d3ea2915af2052ddd9abfb6948170cd6");
		headers.add("cookie", "sessionid=a0a5d6f5f98572df4678ca26d703f98b");
		headers.add("cookie", "sessionid_ss=a0a5d6f5f98572df4678ca26d703f98b");
		headers.add("cookie", "sid_guard=a0a5d6f5f98572df4678ca26d703f98b%7C1652958175%7C5184000%7CMon%2C+18-Jul-2022+11%3A02%3A55+GMT");
		headers.add("cookie", "sid_tt=a0a5d6f5f98572df4678ca26d703f98b");
		headers.add("cookie", "uid_tt=cad870c5f8970ab4266b76415f1c3cefc1b2de89b9b1570c7eee5065282eacd5");
		headers.add("cookie", "uid_tt_ss=cad870c5f8970ab4266b76415f1c3cefc1b2de89b9b1570c7eee5065282eacd5");
		headers.add("cookie", "install_id=7099400845528074030");
		headers.add("cookie", "ttreq=1$cef6647f77990679e41e74b31d2a772feb0fdb1e");
		headers.add("cookie", "store-idc=useast5");
		headers.add("cookie", "store-country-code=us");
		headers.add("cookie", "tt-target-idc=useast5");
		headers.add("cookie", "msToken=w40IXnAg1GfeBH_TZfNL5g3QzpKo31AlBmFvvnVBwNsFe1YHuS02vA0hsjXM-wsB18g5VY6W_SpUatMRN4F5jDnLXqh_SfaVqe39xZEzJQ==");
		headers.add("x-argus", xArgusStr);
		headers.add("x-gorgon", x_gorgon);
		headers.add("x-khronos", ""+x_khronos);
		headers.add("x-ladon", x_ladon);
		
		Request request = new Request.Builder()
				.url(url + "?" + query)
				.headers(headers.build())
				.post(RequestBody.create(null, body))
				.build();
				
		OkHttpClient client = HttpClientFactory.newHttpClient();
		Response response = client.newCall(request).execute();
		byte[] data = response.body().bytes();
		if(GZipUtil.isGZIPBuff(data)){
			data = GZipUtil.decompress(data);
		}
		System.out.println(new String(data));
	}
}
