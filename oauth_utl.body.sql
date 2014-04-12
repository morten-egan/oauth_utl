set scan off;
create or replace package body oauth_utl

as

	oauth_nonce						varchar2(500) 			:= null;
	oauth_timestamp					varchar2(500) 			:= null;
	oauth_http_method				varchar2(10) 			:= 'POST';
	oauth_callback					varchar2(10)			:= 'oob';
	oauth_base_string				varchar2(32000)			:= null;
	oauth_key						varchar2(500)			:= null;
	oauth_signature_sha1			raw(2000)				:= null;
	oauth_signature_sha1_base64		varchar2(500)			:= null;
	oauth_header					varchar2(4000)			:= null;

	-- Client settings
	oauth_consumer_key				varchar2(4000)			:= null;
	oauth_consumer_secret			varchar2(4000)			:= null;

	-- Endpoints
	oauth_request_token_url			varchar2(4000)			:= 'http://www.ide.ufv.br:8008/i3geo/pacotes/linkedinoauth/example/request_token.php';
	oauth_access_token_url			varchar2(4000)			:= null;
	oauth_resource_url				varchar2(4000)			:= null;

	-- Request URLs
	oauth_request_url				varchar2(4000)			:= null;

	-- HTTP Types
	oauth_request					utl_http.req;
	oauth_response					utl_http.resp;
	oauth_header_name				varchar2(4000);
	oauth_header_val				varchar2(4000);
	oauth_body_line					varchar2(4000);

	function real_url_encode (
		str_in						in				varchar2
	)
	return varchar2
	
	as
	
		l_ret_val			varchar2(4000);
		l_bad   			varchar2(100) default ' >%}\~];?@&<#{|^[`/:=$+''"';  
    	l_char  			char(1);  
	
	begin
	
		dbms_application_info.set_action('real_url_encode');

		for i in 1 .. nvl(length(str_in),0) loop  
			l_char :=  substr(str_in,i,1);  
			if ( instr( l_bad, l_char ) > 0 ) then  
				l_ret_val := l_ret_val || '%' ||  to_char( ascii(l_char), 'fmXX' );  
			else  
				l_ret_val := l_ret_val || l_char;  
			end if;  
		end loop;
	
		dbms_application_info.set_action(null);
	
		return l_ret_val;
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;
	
	end real_url_encode;

	procedure generate_nonce

	as

	begin

		oauth_nonce := dbms_random.string('A', 15);
		oauth_nonce := real_url_encode(utl_encode.base64_encode(utl_i18n.string_to_raw (oauth_nonce, 'AL32UTF8')));

	end generate_nonce;

	procedure generate_timestamp

	as

	begin

		dbms_application_info.set_action('generate_timestamp');

		oauth_timestamp := real_url_encode(round(((sysdate - to_date('01-01-1970', 'DD-MM-YYYY'))  * (86400)) - 7200));

		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;

	end generate_timestamp;

	procedure generate_base
	
	as
	
	begin
	
		dbms_application_info.set_action('generate_base');

		oauth_base_string := 	oauth_http_method
								|| '&'
								|| real_url_encode(oauth_request_token_url)
								|| real_url_encode(
									'&oauth_consumer_key='
									|| oauth_consumer_key
									|| '&oauth_nonce='
									|| oauth_nonce
									|| '&oauth_signature_method='
									|| oauth_utl.oauth_signature_method
									|| '&oauth_timestamp='
									|| oauth_timestamp
									|| '&oauth_version='
									|| oauth_utl.oauth_version
								);
		
		dbms_output.put_line(oauth_base_string);
	
		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;
	
	end generate_base;

	procedure generate_signature
	
	as
	
	begin
	
		dbms_application_info.set_action('generate_signature');

		oauth_signature_sha1 := dbms_crypto.mac (
									src 	=> utl_i18n.string_to_raw (oauth_base_string, 'AL32UTF8'),
                                	typ		=> dbms_crypto.hmac_sh1,
                                	key		=> utl_i18n.string_to_raw (oauth_key, 'AL32UTF8')
                            	);

		oauth_signature_sha1_base64 := utl_raw.cast_to_varchar2(utl_encode.base64_encode(oauth_signature_sha1));

		dbms_output.put_line('Base64 Signature: ' || oauth_signature_sha1_base64);
	
		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;
	
	end generate_signature;

	procedure generate_request_token_url
	
	as
	
	begin
	
		dbms_application_info.set_action('generate_request_token_url');

		oauth_request_url := 	oauth_request_token_url
								|| '?oauth_consumer_key='
								|| oauth_consumer_key
								|| '&oauth_nonce='
								|| oauth_nonce
								|| '&oauth_signature='
								|| real_url_encode(oauth_signature_sha1_base64)
								|| '&oauth_signature_method='
								|| oauth_utl.oauth_signature_method
								|| '&oauth_timestamp='
								|| oauth_timestamp
								|| '&oauth_version='
								|| oauth_version;

		dbms_output.put_line('Full request token url: ' || oauth_request_url);
	
		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;
	
	end generate_request_token_url;

	procedure generate_oauth_header
	
	as
	
	begin
	
		dbms_application_info.set_action('generate_oauth_header');

		oauth_header := 	'Authorization: OAuth oauth_nonce="' || oauth_nonce || '", '
							|| 'oauth_signature_method="'|| oauth_utl.oauth_signature_method || '", '
							|| 'oauth_timestamp="'|| oauth_timestamp || '", '
							|| 'oauth_consumer_key="'|| oauth_consumer_key || '", '
							|| 'oauth_signature="' || real_url_encode(oauth_signature_sha1_base64) || '", '
							|| 'oauth_version="' || oauth_utl.oauth_version || '"';

		dbms_output.put_line('Oauth header: ' || oauth_header);
	
		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;
	
	end generate_oauth_header;

	procedure send_request
	
	as
	
	begin
	
		dbms_application_info.set_action('send_request');

		-- Extended error checking
		utl_http.set_response_error_check(
			enable => true
		);
		utl_http.set_detailed_excp_support(
			enable => true
		);

		oauth_request := utl_http.begin_request (
			url		=>	oauth_request_url,
			method	=>	oauth_http_method
		);

		utl_http.set_header (
			r		=>	oauth_request,
			name	=>	'Authorization',
			value	=>	oauth_header
		);

		utl_http.write_text (
			r		=>	oauth_request,
			data	=>	''
		);

		-- Now we can get the output and parse it.
		oauth_response := utl_http.get_response (
			r		=>	oauth_request
		);

		-- Header parse
		for i in 1..utl_http.get_header_count(oauth_response) loop
			utl_http.get_header (
				r => oauth_response
				, n => i
				, name => oauth_header_name
				, value => oauth_header_val
			);
			dbms_output.put_line(oauth_header_name || ': ' || oauth_header_val);
		end loop;

		-- Content parse
		begin
			loop
				utl_http.read_line (
					r			=>	oauth_response,
					data		=>	oauth_body_line,
					remove_crlf	=>	true
				);
				dbms_output.put_line(oauth_body_line);
			end loop;

			exception
				when utl_http.end_of_body then
					null;
		end;

		utl_http.end_response(
			r 		=>	oauth_response
		);
	
		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				dbms_output.put_line('HTTP ERROR: ' || utl_http.get_detailed_sqlerrm);
				utl_http.end_response(
					r 		=>	oauth_response
				);
	
	end send_request;

	procedure oauth1 (
		client_key						in				varchar2
		, client_secret					in				varchar2
	)
	
	as
	
	begin
	
		dbms_application_info.set_action('oauth1');

		-- Setting parms
		oauth_consumer_key := client_key;
		oauth_consumer_secret := client_secret;
		oauth_key := oauth_consumer_secret || '&';

		generate_nonce;
		generate_timestamp;
		generate_base;
		generate_signature;
		generate_request_token_url;
		generate_oauth_header;
		send_request;
	
		dbms_application_info.set_action(null);
	
		exception
			when others then
				dbms_application_info.set_action(null);
				raise;
	
	end oauth1;


begin

	dbms_application_info.set_client_info('oauth_utl');
	dbms_session.set_identifier('oauth_utl');

end oauth_utl;
/