// src/contract.rs
use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, StdError,
};

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, ServiceResponse, Attestation, ImageInfo as MsgImageInfo};
use crate::state::{global_state, global_state_read, services, services_read, GlobalState, Service, ImageInfo};

/// Instantiate the contract. This initializes the global state and the services list.
#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> StdResult<Response> {
    // Initialize global state with service_count set to 0.
    let gs = GlobalState { service_count: 0 };
    global_state(deps.storage).save(&gs)?;

    // Initialize an empty list for services.
    let svc_list: Vec<Service> = Vec::new();
    services(deps.storage).save(&svc_list)?;

    Ok(Response::default())
}

/// Execute entry point for handling ExecuteMsg.
#[entry_point]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> StdResult<Response> {
    match msg {
        ExecuteMsg::CreateService { name } => try_create_service(deps, info, name),
        ExecuteMsg::AddImageToService { service_id, image_info } => {
            try_add_image(deps, info, service_id, image_info)
        }
        ExecuteMsg::RemoveImageFromService { service_id, image_info } => {
            try_remove_image(deps, info, service_id, image_info)
        }
        ExecuteMsg::GetSecretKey { service_id, attestation } => {
            try_get_secret_key(deps, info, service_id, attestation)
        }
    }
}

/// Handles the creation of a new service.
/// - Loads the current global state and services list.
/// - Assigns a new ID equal to the current service_count.
/// - Creates a new service with the given name and the caller as admin.
/// - Generates a placeholder secret key (TODO: implement proper generation).
/// - Initializes image_infos as an empty vector.
/// - Saves the updated state and services list.
pub fn try_create_service(deps: DepsMut, info: MessageInfo, name: String) -> StdResult<Response> {
    // Load the global state.
    let mut gs = global_state(deps.storage).load()?;

    // Load the current list of services.
    let mut svc_list = services(deps.storage).load()?;

    // The new service ID is the current service count.
    let service_id = gs.service_count;

    // Create the new service with a placeholder secret key and an empty image_infos vector.
    let new_service = Service {
        id: service_id,
        name: name.clone(),
        admin: info.sender.clone(),
        secret_key: Some("TODO_SECRET_KEY".to_string()), // TODO: Implement secret key generation logic.
        image_infos: Vec::new(),
    };

    // Add the new service to the list.
    svc_list.push(new_service);

    // Increment the global service counter.
    gs.service_count += 1;

    // Save the updated global state and services list.
    global_state(deps.storage).save(&gs)?;
    services(deps.storage).save(&svc_list)?;

    // Return a successful response with attributes for logging.
    Ok(Response::new()
        .add_attribute("action", "create_service")
        .add_attribute("service_id", service_id.to_string())
        .add_attribute("name", name)
        .add_attribute("admin", info.sender.to_string()))
}

/// Handles adding image info to a service.
/// - Validates that the caller is the service admin.
/// - Appends the provided image info into the service's image_infos list.
/// - Records a plain-text log event on-chain with the service id and image info.
pub fn try_add_image(
    deps: DepsMut,
    info: MessageInfo,
    service_id: u64,
    image_info: MsgImageInfo,
) -> StdResult<Response> {
    // Load the current list of services.
    let mut svc_list = services(deps.storage).load()?;

    // Limit the mutable borrow scope to extract the formatted image info string.
    let image_info_str = {
        let service = svc_list.iter_mut().find(|s| s.id == service_id)
            .ok_or_else(|| StdError::generic_err("Service not found"))?;

        // Check if the caller is the service admin.
        if info.sender != service.admin {
            return Err(StdError::generic_err("Only the service admin can add image info"));
        }

        // Append the new image info into the service's image_infos list.
        service.image_infos.push(ImageInfo {
            var1: image_info.var1,
            var2: image_info.var2,
            var3: image_info.var3,
        });

        // Clone the last added image info values for logging.
        let last = service.image_infos.last().unwrap();
        format!("{{var1: {}, var2: {}, var3: {}}}", last.var1, last.var2, last.var3)
    };

    // Now the mutable borrow is dropped; we can safely save the updated services list.
    services(deps.storage).save(&svc_list)?;

    // Return a response with a log event.
    Ok(Response::new()
        .add_attribute("action", "add_image_to_service")
        .add_attribute("service_id", service_id.to_string())
        .add_attribute("image_info", image_info_str))
}

/// Handles removing image info from a service.
/// - Validates that the caller is the service admin.
/// - Removes the image info from the service's image_infos list if it matches the provided data.
pub fn try_remove_image(
    deps: DepsMut,
    info: MessageInfo,
    service_id: u64,
    image_info: MsgImageInfo,
) -> StdResult<Response> {
    // Load the current list of services.
    let mut svc_list = services(deps.storage).load()?;

    // Find the service with the given service_id.
    let service = svc_list.iter_mut().find(|s| s.id == service_id)
        .ok_or_else(|| StdError::generic_err("Service not found"))?;

    // Check if the caller is the service admin.
    if info.sender != service.admin {
        return Err(StdError::generic_err("Only the service admin can remove image info"));
    }

    // Remove the image info that matches the provided data.
    let original_len = service.image_infos.len();
    service.image_infos.retain(|img| {
        !(img.var1 == image_info.var1 &&
            img.var2 == image_info.var2 &&
            img.var3 == image_info.var3)
    });

    if service.image_infos.len() == original_len {
        return Err(StdError::generic_err("Image info with given parameters not found"));
    }

    // Save the updated services list.
    services(deps.storage).save(&svc_list)?;

    // Return a response with a log event.
    Ok(Response::new()
        .add_attribute("action", "remove_image_from_service")
        .add_attribute("service_id", service_id.to_string()))
}

/// Handles getting the secret key for a service.
/// - Validates the provided attestation by calling a stubbed dcap_verify_quote function.
/// - Checks if the service has associated image info (stub logic).
/// - If valid, encrypts the secret key using the ephemeral key from the attestation (stubbed) and returns it.
pub fn try_get_secret_key(
    deps: DepsMut,
    _info: MessageInfo,
    service_id: u64,
    attestation: Attestation,
) -> StdResult<Response> {
    // Load the current list of services.
    let svc_list = services(deps.storage).load()?;

    // Find the service with the given service_id.
    let service = svc_list.into_iter().find(|s| s.id == service_id)
        .ok_or_else(|| StdError::generic_err("Service not found"))?;

    // Stub: Verify the attestation (using a precompiled dcap_verify_quote method placeholder).
    if !dcap_verify_quote(&attestation) {
        return Err(StdError::generic_err("Attestation verification failed"));
    }

    // Stub: Check if image_infos is not empty (to simulate that images are associated).
    if service.image_infos.is_empty() {
        return Err(StdError::generic_err("No image info associated with the service"));
    }

    // Retrieve the secret key (assuming it is set).
    let secret_key = service.secret_key.ok_or_else(|| StdError::generic_err("Secret key not set"))?;

    // Stub: Encrypt the secret key with the ephemeral key from the attestation (dummy encryption).
    let encrypted_secret_key = format!("encrypted_{}_with_{}", secret_key, attestation.report_data);

    // Return the encrypted secret key in the response attributes.
    Ok(Response::new()
        .add_attribute("action", "get_secret_key")
        .add_attribute("service_id", service_id.to_string())
        .add_attribute("encrypted_secret_key", encrypted_secret_key))
}

/// Stub function for attestation verification.
/// In a real implementation, this would call the precompiled dcap_verify_quote method.
fn dcap_verify_quote(_attestation: &Attestation) -> bool {
    // TODO: Implement actual attestation verification logic.
    true
}

/// Query entry point for handling QueryMsg.
#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetService { id } => to_binary(&query_service(deps, id)?),
        QueryMsg::ListServices {} => to_binary(&query_services(deps)?),
    }
}

/// Returns information about a service by its ID.
fn query_service(deps: Deps, id: u64) -> StdResult<ServiceResponse> {
    let svc_list = services_read(deps.storage).load()?;
    let service = svc_list
        .into_iter()
        .find(|s| s.id == id)
        .ok_or_else(|| StdError::generic_err("Service not found"))?;
    Ok(ServiceResponse {
        id: service.id,
        name: service.name,
        admin: service.admin.to_string(),
    })
}

/// Returns a list of all services.
fn query_services(deps: Deps) -> StdResult<Vec<ServiceResponse>> {
    let svc_list = services_read(deps.storage).load()?;
    let resp: Vec<ServiceResponse> = svc_list
        .into_iter()
        .map(|s| ServiceResponse {
            id: s.id,
            name: s.name,
            admin: s.admin.to_string(),
        })
        .collect();
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{from_binary, StdError};

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies();
        let info = mock_info("creator", &[]);
        let init_msg = InstantiateMsg {};

        let res = instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();
        assert_eq!(0, res.messages.len());

        // Query services list should be empty.
        let res = query(deps.as_ref(), mock_env(), QueryMsg::ListServices {}).unwrap();
        let services_list: Vec<ServiceResponse> = from_binary(&res).unwrap();
        assert_eq!(services_list.len(), 0);
    }

    #[test]
    fn create_service() {
        let mut deps = mock_dependencies();
        let info = mock_info("creator", &[]);
        let init_msg = InstantiateMsg {};

        let _ = instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg).unwrap();

        let exec_msg = ExecuteMsg::CreateService { name: "TestService".to_string() };
        let res = execute(deps.as_mut(), mock_env(), info.clone(), exec_msg).unwrap();

        // Check response attributes.
        assert!(res.attributes.iter().any(|attr| attr.key == "action" && attr.value == "create_service"));

        // Query the service and check values.
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetService { id: 0 }).unwrap();
        let service: ServiceResponse = from_binary(&res).unwrap();
        assert_eq!(service.name, "TestService");
        assert_eq!(service.admin, "creator");
    }

    #[test]
    fn add_and_remove_image() {
        let mut deps = mock_dependencies();
        let admin_info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        let _ = instantiate(deps.as_mut(), mock_env(), admin_info.clone(), init_msg).unwrap();

        // Create service by admin.
        let create_msg = ExecuteMsg::CreateService { name: "ServiceWithImage".to_string() };
        let _ = execute(deps.as_mut(), mock_env(), admin_info.clone(), create_msg).unwrap();

        // Add image to service 0.
        let image_info = MsgImageInfo {
            var1: "v1".to_string(),
            var2: "v2".to_string(),
            var3: "v3".to_string(),
        };
        let add_image_msg = ExecuteMsg::AddImageToService { service_id: 0, image_info: image_info.clone() };
        let res = execute(deps.as_mut(), mock_env(), admin_info.clone(), add_image_msg).unwrap();
        assert!(res.attributes.iter().any(|attr| attr.key == "action" && attr.value == "add_image_to_service"));

        // Remove image from service 0.
        let remove_image_msg = ExecuteMsg::RemoveImageFromService { service_id: 0, image_info };
        let res = execute(deps.as_mut(), mock_env(), admin_info.clone(), remove_image_msg).unwrap();
        assert!(res.attributes.iter().any(|attr| attr.key == "action" && attr.value == "remove_image_from_service"));
    }

    #[test]
    fn get_secret_key() {
        let mut deps = mock_dependencies();
        let admin_info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        let _ = instantiate(deps.as_mut(), mock_env(), admin_info.clone(), init_msg).unwrap();

        // Create service by admin.
        let create_msg = ExecuteMsg::CreateService { name: "ServiceForKey".to_string() };
        let _ = execute(deps.as_mut(), mock_env(), admin_info.clone(), create_msg).unwrap();

        // Add image info to service to satisfy condition for secret key retrieval.
        let image_info = MsgImageInfo {
            var1: "v1".to_string(),
            var2: "v2".to_string(),
            var3: "v3".to_string(),
        };
        let add_image_msg = ExecuteMsg::AddImageToService { service_id: 0, image_info };
        let _ = execute(deps.as_mut(), mock_env(), admin_info.clone(), add_image_msg).unwrap();

        // Get secret key with a dummy attestation.
        let attestation = crate::msg::Attestation { report_data: "ephemeral_key".to_string() };
        let get_key_msg = ExecuteMsg::GetSecretKey { service_id: 0, attestation: attestation.clone() };
        let res = execute(deps.as_mut(), mock_env(), admin_info.clone(), get_key_msg).unwrap();

        // Check that the response contains the encrypted secret key attribute.
        let encrypted_key_attr = res.attributes.iter().find(|attr| attr.key == "encrypted_secret_key");
        assert!(encrypted_key_attr.is_some());
        let encrypted_key = &encrypted_key_attr.unwrap().value;
        // Check that the encrypted key string contains both the TODO_SECRET_KEY and the report_data.
        assert!(encrypted_key.contains("TODO_SECRET_KEY"));
        assert!(encrypted_key.contains(&attestation.report_data));
    }

    #[test]
    fn unauthorized_add_image() {
        let mut deps = mock_dependencies();
        let admin_info = mock_info("admin", &[]);
        let other_info = mock_info("other", &[]);
        let init_msg = InstantiateMsg {};
        let _ = instantiate(deps.as_mut(), mock_env(), admin_info.clone(), init_msg).unwrap();

        // Create service by admin.
        let create_msg = ExecuteMsg::CreateService { name: "UnauthorizedTest".to_string() };
        let _ = execute(deps.as_mut(), mock_env(), admin_info.clone(), create_msg).unwrap();

        // Try to add image info from a non-admin account.
        let image_info = MsgImageInfo {
            var1: "v1".to_string(),
            var2: "v2".to_string(),
            var3: "v3".to_string(),
        };
        let add_image_msg = ExecuteMsg::AddImageToService { service_id: 0, image_info };
        let res = execute(deps.as_mut(), mock_env(), other_info.clone(), add_image_msg);
        match res {
            Err(StdError::GenericErr { msg, .. }) => {
                assert_eq!(msg, "Only the service admin can add image info");
            },
            _ => panic!("Expected unauthorized error"),
        }
    }
}
