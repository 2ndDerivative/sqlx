use std::borrow::Cow;

use crate::{
    connection::PgStream,
    message::{Authentication, GssResponse},
    PgConnectOptions,
};
use cross_krb5::{ClientCtx, InitiateFlags, Step};
use sqlx_core::Error;

pub async fn authenticate(stream: &mut PgStream, options: &PgConnectOptions) -> Result<(), Error> {
    let client_principal: Option<&str> = options.gssapi_options.gssapi_client_principal.as_deref();

    let target_principal: Cow<str> = options
        .gssapi_options
        .gssapi_target_principal
        .as_deref()
        .map(Cow::Borrowed)
        .unwrap_or_else(|| Cow::Owned(format!("postgres/{}", options.host)));

    let channel_binding_token = stream.channel_binding_token();
    let (mut pending_ctx, first_token) = ClientCtx::new(
        InitiateFlags::default(),
        client_principal,
        &target_principal,
        channel_binding_token.as_deref(),
    )
    .map_err(|e| Error::GSSAPI(e.into_boxed_dyn_error()))?;
    stream
        .send(GssResponse {
            token: &first_token,
        })
        .await?;

    loop {
        let response = match stream.recv_expect().await? {
            Authentication::Ok => break,
            Authentication::GssContinue(cont) => cont,
            auth => {
                return Err(err_protocol!(
                    "expected GSSContinue but received {:?}",
                    auth
                ));
            }
        };
        pending_ctx = match pending_ctx
            .step(response.token())
            .map_err(|e| Error::GSSAPI(e.into_boxed_dyn_error()))?
        {
            Step::Continue((new_ctx, new_token)) => {
                let token = new_token.as_ref();
                stream.send(GssResponse { token }).await?;
                new_ctx
            }
            Step::Finished((_finished, last_token)) => {
                if let Some(token) = last_token.as_ref() {
                    stream.send(GssResponse { token }).await?;
                }
                // With no final token, just wait

                match stream.recv_expect().await? {
                    Authentication::Ok => break,
                    auth => {
                        return Err(err_protocol!(
                            "expected to have finished authentication but received {:?}",
                            auth
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}
