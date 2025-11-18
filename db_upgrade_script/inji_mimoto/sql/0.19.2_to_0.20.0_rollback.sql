-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_mimoto
-- Table Name : trusted_verifiers
-- Purpose    : To drop the trusted_verifiers table that was created in 0.14.x_to_0.15.x_upgrade.sql to make it backward compatibility
--
-- Create By   	: Bhargavi Puvvada, Durgesh Konga
-- Created Date	: 11-sep-2025
--
-- Modified Date        Modified By         Comments / Remarks
-- 07-Oct-2025          Durgesh Konga       Added verifiable_presentations table to make it backward compatibility
-- ------------------------------------------------------------------------------------------
-- ------------------------------------

-- Drop table for trusted_verifiers
DROP TABLE IF EXISTS trusted_verifiers;

-- Drop table for verifiable_presentations
DROP TABLE IF EXISTS verifiable_presentations;