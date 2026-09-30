use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::server::state::AppState;

pub mod spire {
    pub mod server {
        pub mod upstreamauthority {
            pub mod v1 {
                tonic::include_proto!("spire.server.upstreamauthority.v1");
            }
        }
    }
}

#[derive(Clone)]
pub struct UpstreamAuthorityService {
    pub state: Arc<AppState>,
}

#[tonic::async_trait]
impl spire::server::upstreamauthority::v1::upstream_authority_server::UpstreamAuthority
    for UpstreamAuthorityService
{
    async fn mint_x509_ca(
        &self,
        request: Request<spire::server::upstreamauthority::v1::MintX509CARequest>,
    ) -> Result<Response<spire::server::upstreamauthority::v1::MintX509CAResponse>, Status> {
        let req = request.into_inner();

        let actor = crate::domain::keys::models::ServiceId("spire".to_string());
        let csr_pem = req.csr_pem.clone();

        let result = crate::application::use_cases::sign_intermediate_ca::SignIntermediateCaUseCase::new(
            Arc::new(crate::domain::audit::service::AuditService::new(
                Arc::new(kms_db::repositories::PgAuditRepository::new(self.state.db.clone())),
            )),
        )
        .execute(
            &self.state,
            crate::application::use_cases::sign_intermediate_ca::SignIntermediateCaInput {
                caller_service: actor,
                ca_tag: "root".to_string(),
                csr_pem,
                validity_days: 3650,
            },
        )
        .await
        .map_err(|e| Status::internal(format!("CA signing failed: {e}")))?;

        let root_cert = match kms_db::repositories::RootCaQueries::fetch_active_by_tag(
            &self.state.db,
            "root",
        )
        .await
        .map_err(|e| Status::internal(format!("root CA query failed: {e}")))?
        {
            Some(row) => row.certificate_pem,
            None => return Err(Status::failed_precondition("root CA certificate not found")),
        };

        Ok(Response::new(
            spire::server::upstreamauthority::v1::MintX509CAResponse {
                x509_ca_chain: vec![result.certificate_pem, root_cert],
            },
        ))
    }
}
