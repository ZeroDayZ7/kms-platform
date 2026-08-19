// Copyright 2026 ZeroDayZ7
// Licensed under the Apache License, Version 2.0
// See LICENSE file for details.

pub mod app_error;

pub use app_error::AppError;

pub type AppResult<T> = Result<T, AppError>;
