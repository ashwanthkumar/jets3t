/*
 * JetS3t : Java S3 Toolkit
 * Project hosted at http://bitbucket.org/jmurty/jets3t/
 *
 * Copyright 2007 James Murty
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
 */
package org.jets3t.gui.skins.html;

import java.util.Properties;

import javax.swing.JTable;

/**
 * A skinned JTable, which is actually just a standard JTable - useful only as a
 * base for someone to specialise.
 *
 * @author James Murty
 */
public class SkinnedJTable extends JTable {

    private static final long serialVersionUID = -8799193197737732023L;

    public SkinnedJTable(Properties skinProperties, String itemName) {
        super();
    }

}
