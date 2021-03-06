/*
 * (C) Copyright 2015 Nuxeo SA (http://nuxeo.com/) and others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *     Florent Guillaume
 */
package org.nuxeo.ecm.platform.annotations.service;

import org.nuxeo.ecm.core.test.CoreFeature;
import org.nuxeo.runtime.api.Framework;
import org.nuxeo.runtime.test.runner.Deploy;
import org.nuxeo.runtime.test.runner.Features;
import org.nuxeo.runtime.test.runner.FeaturesRunner;
import org.nuxeo.runtime.test.runner.LocalDeploy;
import org.nuxeo.runtime.test.runner.SimpleFeature;

@Features(CoreFeature.class)
@Deploy({ "org.nuxeo.ecm.relations.api", //
        "org.nuxeo.ecm.relations", //
        "org.nuxeo.ecm.relations.jena", //
        "org.nuxeo.ecm.annotations", //
        "org.nuxeo.ecm.annotations.contrib", //
        "org.nuxeo.runtime.datasource", //
})
@LocalDeploy({ "org.nuxeo.ecm.annotations:test-ann-contrib.xml", //
        "org.nuxeo.ecm.annotations:datasource-config.xml" })
public class AnnotationFeature extends SimpleFeature {

    @Override
    public void initialize(FeaturesRunner runner) {
        Framework.addListener(new AnnotationsJenaSetup());
    }
}
