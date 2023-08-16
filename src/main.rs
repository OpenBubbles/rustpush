
use std::rc::Rc;

use apns::APNSState;
use ids::user::{IDSState, get_handles};
use imessage::IMClient;
use plist::Dictionary;
use tokio::{fs, io::{self, BufReader, AsyncBufReadExt}};
use tokio::io::AsyncWriteExt;
use util::{base64_encode, base64_decode};
use crate::ids::identity::IDSIdentity;

use tokio::time::{sleep, Duration};

use crate::apns::APNSConnection;
use crate::ids::user::IDSUser;
use serde::{Serialize, Deserialize};
mod bags;
mod albert;
mod apns;
mod ids;
mod util;
mod imessage;

#[derive(Serialize, Deserialize, Clone)]
struct SavedState {
    push: APNSState,
    auth: IDSState
}

#[tokio::main]
async fn main() {
    //get_handles("D:8301788944", &(base64_decode("MIIEogIBAAKCAQEAvEsHtwz7CSBHXWqsSotT6XsuBR1u77Xfh1Liuf2TDR6pe833QYNW1qRmt4QUW6P8nR/qQepX0qxEB/JCmndYK28h964RVOrgx1Byu7cdEv/xXqnaXzHBonmKmZx3nrVxG0rs51MDbEB2G6wYFUcD8Hr4DQaS8ESrofJr2OIa37jiU10ElwWjNNgvNoxKJbshXKfW7S8E9fbTRLSNEgoi/qc3UWBjCjtOT/s600PlTuM3aGSL4EHyRmGYviQ/w9oeGXQdjOWNIHS+5Xb+Dw7LfVWseN2plGp14Q78r/l6Ge/jSUbHdxl7FaSh11VsU8w3c59yI0tg99yeZzEyu+IIgwIDAQABAoIBAAFpYUIYENG9XODwacuX8SXGTKQGgncS7/1oZla/9e2alelds/AudzozZVRpjcAvdzdeWTfr9S3ufga+juKa6R2k6aZHtyLh1+mRStWUG92xRDKnfKxLXTObTFS2fZcXrnoRPRFxkoxUjLjMY38qrHbjFR+pNZ942aiPKWEo4MwIktfI7sVG6VA53NHBVSlO+bA1ejdkC7uIReEzJuNhE4QAGm9c/7vKVEBYJmItSmrrBjVGQQOp1Y6N89W9WNd5+tVFDepDAahncTGO0MMQ5KtKZe5IUdfypsBnpYN3J86+Ye/poNbLVBjmIILmjElXwzD1bc3hgCgCNoHc/roR13ECgYEA6utBn27m2zSTNDsouCMC3pc6gSJQFNG/qhnQU6bUIKnlkt9Rb9haJRcvPP9qL6oQyGzF8rmN23Q5MgZQYe5YrXuAPQOpwQI5H2GCLg4LCNhE1tu9Z+m4+angiM5MHQ+mNGCKma+CmHOqWFVBsPoBkN6S5CbahD3oSSTrJK07Vk0CgYEAzTClszO/pV4jFvgu/Vs5TfbWtY6kWDhb8Hnl6krs8iOhdXu7XGEWSNPa5Veq2rOzoH+4f9Zesu2B0NJOLf230C7bo8IRHVvWDtep9vgpwoyK0GVrOCYX8Adi8hYgXnttGyE7nQ9nhyj7SgPIbqRyfenT4sC192GIu1dfzIwY4g8CgYB0aiL5/D5g8LvmDU8PeSIp5m1youtmdc7yX5pyaeEDUs5Wq14y+9coPEYHh1c6yZ9Jg0XRFAztbLoPRTu+XBwL1IDnO5J6+DwQhgS6B/GF746lnv1MqnElH/8KLJlhaWjm2dS1dllUbTVEUvOb3Ti7buECORLep8MdxDLW2RXnnQKBgF42Ru6YBReduIjUXWbw2sfkXUMxgl4LSpOItLs1ucOX/otdy3IoFb5Mn8YL0aPnPMOlwQXZXNPU33UNCt5tD1fkG+79rTQItalM9noyCaKNOzNiTa+TNgx8p7610BjxnPAG+0MrDoLtmyupvv6mPPd5RFNp3mL+gnRaMt9NOCObAoGAIVS01gLVlIQVxWX/6SBIfCvkduFDZh/omm2PwShk2QAe7z+R3j1auNCsF1SLwv5aJzt6E6Grct7b6UdvPUdxEuEs5I8VNvFDemv8kVrGtwlRZwaUBlSEJDZrUUm67m5mzAPWRaRyT/jq6H/dXl947k4cY5qEdGJn3rlvWyUZW9s="),
    //base64_decode("MIIJJzCCCA+gAwIBAgIRAMpBSYI6QxHu//////////8wDQYJKoZIhvcNAQEFBQAwbjELMAkGA1UEBhMCVVMxEzARBgNVBAoMCkFwcGxlIEluYy4xEjAQBgNVBAsMCUFwcGxlIElEUzEOMAwGA1UEDwwFZHMtaWQxJjAkBgNVBAMMHUFwcGxlIElEUyBEUy1JRCBSZWFsbSBDQSAtIFIxMB4XDTIzMDgxNDAxNDIxMloXDTMzMDgxMTAxNDIxMlowWzELMAkGA1UEBhMCVVMxEzARBgNVBAoMCkFwcGxlIEluYy4xCTAHBgNVBAsMADEOMAwGA1UEDwwFZHMtaWQxHDAaBgoJkiaJk/IsZAEBDAxEOjgzMDE3ODg5NDQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8Swe3DPsJIEddaqxKi1Ppey4FHW7vtd+HUuK5/ZMNHql7zfdBg1bWpGa3hBRbo/ydH+pB6lfSrEQH8kKad1grbyH3rhFU6uDHUHK7tx0S//FeqdpfMcGieYqZnHeetXEbSuznUwNsQHYbrBgVRwPwevgNBpLwRKuh8mvY4hrfuOJTXQSXBaM02C82jEoluyFcp9btLwT19tNEtI0SCiL+pzdRYGMKO05P+zrTQ+VO4zdoZIvgQfJGYZi+JD/D2h4ZdB2M5Y0gdL7ldv4PDst9Vax43amUanXhDvyv+XoZ7+NJRsd3GXsVpKHXVWxTzDdzn3IjS2D33J5nMTK74giDAgMBAAGjggXRMIIFzTCCBUkGA1UdEQSCBUAwggU8oCAGCiqGSIb3Y2QGBAQDEgADAAAAAQAAAAAAAAZeAAAAAKCCBRYGCiqGSIb3Y2QGBAcDggUGAEZVU1AAP4ZEr8asNDtP/3aWC3ZJKGHe/GyLP9wU7/Qd+1NoLmkQ5tzlOcObxKuKV4a92fgFhM2bFKLpMkIo7VxBilNxRKHcicYiqxrZGI482fG83tnOsP77JV0Bj1nRSlqL1O8rFpTCm+QaADWdVvaRbpc0OAUikmpRnWlpDHaTC2mf4GQqkvuBNmG8OcJJO/snlAoEaNwKnKhoKAvEzYoomqFrQhGX27adz/Oy+eCaRqhGuT4nOZH3aeOn7mU/HMkdLbVUTB/FQs0teuwzR3e9/dYskKRgecGTjlXfN5eB9SuhA/0T59MaSd3iK/KjqgdYH8bKRgUwGvrsH2vsgfo90etixGeKF7vMsMeUgnnEScDMMPSL6WHIBBcPxA1jrpndbIQdlo5kHXhGXT1iYRM79H7gE1tkLKbkNcTGeg4D++EnsH824UvaDeI1IMC2vJcKOvvUelhdqln7UxL1h4NI1uUJWt94hVGO2NOj972puTvRm5FkyztX3OAwWh8u8YCYI9B3pYMit1Vd8jkMJqJ4ZVkvP8oydG2zLUHWWLXe9Jnx8lNogg6ywhsbBo3phOg3dqzQ+WZm5TTYx+k+Cv6Yt048APDXxJUUvProSL9yLjOv86kTGLXzXFKyiVE8oDFWdcByEqd9xSEOUFW3iaeL95XgqcSu66cWYfXw3mQbKjTVzwAyKkZmxLA7m0dOO04MfkGOHU0diBqCXFT8tEEbYkiZ0ynNkBz1UBSr5HADgFcW5i6syTvD1m+i5L/0+EZKlCKtPHB5KTIf3Id8412scsE9hzlu+iO+4nbcSP4GgQ+0rQlE++JA3oYSbQRs/AJ9tczg2GDCUFnCnXmkWUAjFKxQXAcxlL8qWL4aLKiBEQjvVZyKRu169LDuZOr+9NcSkeRDe50TdGBQpCZ7ICesjly0QaFbUUwez5yJ+IS5RAeIlUiCIJWGVUgZIHKGxdtvgkbIX3q74Lf3s0dRS47yGklaRSdGcvzh5HjtzKCo36qT6+XirguJfHSf9DNSvqWKwjzcYxt1yBEth6nXZ03XvF3Qzftrdy6Gsz30MeF7ppViSen/Tp+Uct4RVXXyOgG2JqfWgswu+pHDIqy6IGUXc9NJYX7RC8zSlq4BSPoaAuef/kqnzdb+U6xOkvv4PU0ace8wikEG8KDgFweXq5mvsdaQ/yGNhOcgm1TFYB3oB78zldRrmySiafpA0fiiE1choFv/I9yBLXajiHn/uEKgo+NEir7n91DUn3f7k5G5CQWNjp0uZlwkk5166EppW2T2bfRQWBC5JseP/9gPYBnOLTych5rlOP8Q+KjaSMOga3AlQfHo15zcNzvbv9/z0kQlYNgWbblQNdOQx78YoXtdPq3T19Nnmo8ymq1ahLu3vkvxEfpz+f0SEFn5rNRXATFaf5LvvifU4tWv6UbC7qEysBHQiqMgtiWy3VEAdt2wT2bDHY2j/xrLhXlCZ0URb3rqLZfLKY3KmYb/TY/Y3L3UwMgIwe6ob6VhviWrvOSLVCoU0tWPCVeqQcBIvkc957en5SirCiFnV3sSmdZv0Vex0P1CrmHrmViktiYLEXVPGPS80quNIk4y+DqHfmt8pxmh7nxfPLD/WZ8i5U9eELuC7lgdOgGaZr/s74E1TrLC0NcGRvPvrDUtiA58nHN+23zch6S3nLzlUij8x6G/Gkaaq0nZucStzKrNV33WtJM4buCKo+IwHwYDVR0jBBgwFoAUhNNshlgwd2JETKyHiRRE8hyxO2MwHQYDVR0OBBYEFDgZO106W1r7Ql6iU5KdOJu0uDcyMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgP4MCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0BAQUFAAOCAQEAIFVT+BRl8GXCN0zGdxyT1VVvq/VDCOnwObVh9NE3HWvd936vQ9fhAnscJkvlTFuNCz/4PhDnEbGg3Xgw55kdNJdBQx8RIk3WufjuqhG5dvMHjvxlwMwA/QgzbPkOT469Ba3UTGq1XLNiktgddqrQH7uTVA1OwUeoIrAjPQFXULbFGzv58EOqh4vl7jZMXXRuNia+eXDvdcDnfv8+wF5U8GC3hq16dDFCO01IZsao1qRQfsZVlB3sXXqqAHkRB7OSKjOujZfABD7FY/m8KtmFwoaUCiZjOE3nLEqZG18bz+hBhELR5lGB+ZYIdqHYu8R8rLMnoSA7eZtMVqqu/6tm8A==")), 
    //&APNSState { private_key: base64_decode("MIIEogIBAAKCAQEAwrM1f1AVARkP+4j0rshOeJPwbdUV9zaMYLjwiLfoBXsJdskg4zyusfo8Tj1d2NSnAxHNWGQz6dy+Auxloo2yUjrJe3ZMZI6/yl4MLp+Oe0uvjKoF5kKjeH/hRJSb/F9YFWb7vRg6tkLLOgn/KLJl6A7yxkPku69rzv1qZfmom2b6efi66hImM6cvra30PtI+PF0wuZjBVVmeXox2zCamDeaZcFrqjmHro1A8vRXaveOMG79UtI8Ks2YXYHSnnl7oWf5DV058y9KBB8/EPgGuzmm5JwO80S1MHBu3UgFpk7CARIk2sMB3dbx5upjsBJPute4T7nd9LJiTgLxrCn+g2wIDAQABAoIBACUaU6KMV0RbS1Fq2v4Hy/RsdM/pYIM40O2JsMTNDxkkRjxtvaewI7Zk8mMSjLTKaX1LQi+LAN2bJFaYSBH/ILFM5KJze8FZ9rCQ1Y949oUGelC7Ad7MaiyHah1QmJ0yai3B700stduPxPytdQODY6oiVx9zRr6BgnDyl/kQ55GdbBapGvUrUNeDGb0hu4CpQll/yIChs0mLy2Oig6yVMriEwDzPix/FilsJSrF12RMYTi2fkFPysMEejm/iHIptu7aG3/4m3Nnr6wYRb5kFzQWCfgoUW9MfcaX0Ur7qRbNm1gZ0KXJ93bURp+Zk5858TZg00ylSCDgNbk2KdEyuFakCgYEA5LCo8m24mD/R/RwWEx9UTfNsTlJ6T8YkmH9Xj+w26lvSEYZOfykAxw4cwnZz1JjFIFGr/PEM/tWNn3evWaqKKK2TujHNN92QOoKZ80HAv+43+oIiNq+LwBKWjj0FLK4xZZJKP4HtlZARN6Wb9TlvL50yhIpvZ01SUoaBjRxbg50CgYEA2fNuX8Fxbzq8mEE1976qAllBMhc2ogg/EXxI+80fM063bw8iStFztiXnajskleYe3c0IVh0FxdlkIXCEmp/izra28Rds/yOpN73WPagUnY29nLAGEuwqqcBNP3s/6Ob2G22im8oMihB7YBcP+2sGp1l09RQbE3jfl6TMkft0+NcCgYBT8klCHGardJnnmHy97j0rFBUItxvw1qIuXGhPC32pD6WQC0YbRXjkmNiTxZmFS8LotzIz+mQz0z5WcD+s4X4vqm/U5F0Zibpcz/4lHljb210vFr/qZQweqHQdqGaS3SqCx2173HzS7vxy+dbC8J9Q0hpuLsbwG6EBbCB4JRWuvQKBgCWIbFuFHpm/DbdSk46kgPaClF2h7cCdlu7V7mOegV7+kUxI2Oj1hO27PUzn/nbp+CrOIj9iJBpcQ4gWrl9KZW6fvIVsOVL+uydkQ76+cT5oqFyRW5pqnTY6bZMfEHR1QbCbgsM9Wkd0ayqzDgeH+M9c8m06FyeVSzv8H1aMbSplAoGACpY1oAWbsDppQj6/0PsoryPX8UMEfiAoD0i5pFEE9bZaucjkSWT9kf6GakUD/Gab0kD+vqpu8LsWpA7Ur8lbfFn/14j39CxGM8hKni9bAKI3Q6lHWgYKuXmFkSSkltsZ+HZJtSwCNewMGXQVYC6N40H09+DATNha1qwfrFRDCJs="), cert: base64_decode("MIIDdzCCAuCgAwIBAgIKA988Jnjr3QjFKDANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEVMBMGA1UECxMMQXBwbGUgaVBob25lMR8wHQYDVQQDExZBcHBsZSBpUGhvbmUgRGV2aWNlIENBMB4XDTIzMDgxNDAxMzY1OVoXDTI0MDgxNDAxNDE1OVowgYMxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTESMBAGA1UEBwwJQ3VwZXJ0aW5vMRMwEQYDVQQKDApBcHBsZSBJbmMuMQ8wDQYDVQQLDAZpUGhvbmUxLTArBgNVBAMWJDEyNTg0NUVCLTA5QjQtNDQ2OS1CRDBBLTYwMUJDNDgxRDBENzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMKzNX9QFQEZD/uI9K7ITniT8G3VFfc2jGC48Ii36AV7CXbJIOM8rrH6PE49XdjUpwMRzVhkM+ncvgLsZaKNslI6yXt2TGSOv8peDC6fjntLr4yqBeZCo3h/4USUm/xfWBVm+70YOrZCyzoJ/yiyZegO8sZD5Luva879amX5qJtm+nn4uuoSJjOnL62t9D7SPjxdMLmYwVVZnl6Mdswmpg3mmXBa6o5h66NQPL0V2r3jjBu/VLSPCrNmF2B0p55e6Fn+Q1dOfMvSgQfPxD4Brs5puScDvNEtTBwbt1IBaZOwgESJNrDAd3W8ebqY7AST7rXuE+53fSyYk4C8awp/oNsCAwEAAaOBlTCBkjAfBgNVHSMEGDAWgBSy/iEjRIaVannVgSaOcxDYp0yOdDAdBgNVHQ4EFgQUzjmnYUKpdDntyT5LNHpmOTNcmRUwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBAGCiqGSIb3Y2QGCgYEAgUAMA0GCSqGSIb3DQEBBQUAA4GBAMBTtpafdEcpKolSmz9s7+OmbwSqhZ1P745nzLM2M2R9ikgk2FtONHRPELVcLmMJppSEY8LcpA+6fTQHPOEeMIOjjiEngoEfRw5jejUFX4Zpgwx4JccnFOD1/0XircUWR9hEjs7739qVyRptUl/lhjwcMqfI6X7MHa7xknS38dqr"), token: Some(base64_decode("sjdk4GX6w2TobxjeuA3JPrXHxPdvKRQ2zcaIwdvDVeo=")) }).await.unwrap();
    let data = fs::read_to_string("config.json").await.expect("Unable to read file");
    let saved_state: Option<SavedState> = serde_json::from_str(&data).ok();

    let connection = Rc::new(APNSConnection::new(saved_state.as_ref().map(|state| state.push.clone())).await.unwrap());
    connection.submitter.set_state(1).await;
    connection.submitter.filter(&["com.apple.madrid"]).await;

    let mut user = if let Some(state) = saved_state.as_ref() {
        IDSUser::restore_authentication(connection.clone(), state.auth.clone())
    } else {
        let stdin = io::stdin();
        print!("Username: ");
        io::stdout().flush().await.unwrap();
        let mut reader = BufReader::new(stdin);
        let mut username = String::new();
        reader.read_line(&mut username).await.unwrap();
        print!("Password: ");
        io::stdout().flush().await.unwrap();
        let mut password = String::new();
        reader.read_line(&mut password).await.unwrap();

        IDSUser::authenticate(connection.clone(), username.trim(), password.trim(), || async {
            println!("2fa code: ");
            let stdin = io::stdin();
            let mut reader = BufReader::new(stdin);
            let mut code = String::new();
            reader.read_line(&mut code).await.unwrap();
            code.trim().to_string()
        }).await.unwrap()
    };

    if user.state.identity.is_none() {
        println!("Registering new identity...");
        print!("Enter validation data: ");
        io::stdout().flush().await.unwrap();
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut validation = String::new();
        reader.read_line(&mut validation).await.unwrap();
        user.register_id(&connection.state, &validation).await.unwrap();
    }

    //let lookup = user.lookup(connection.clone(), vec!["tel:+17203818329".to_string(),"mailto:tae.hagen@gmail.com".to_string()]).await.unwrap();

    let user = Rc::new(user);
    let client = IMClient::new(connection.clone(), user.clone());

    sleep(Duration::from_millis(10000)).await;
    
    

    let state = SavedState {
        push: connection.state.clone(),
        auth: user.state.clone()
    };
    let serialized = serde_json::to_string(&state).unwrap();
    fs::write("config.json", serialized).await.unwrap();
}
