import './index.css'

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import {createBrowserRouter, RouterProvider} from "react-router-dom";
import {Landing} from "./components/landing.tsx";
import {Layout} from "./components/layout.tsx";
import {NotFound} from "./components/not-found.tsx";

const router = createBrowserRouter([
    {
        path: '/',
        element: <Layout />,
        children: [
            {
                path: '/',
                element: <Landing />,
            },
            {
                path: 'not-found',
                element: <NotFound />
            }
        ]
    }
])

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
)
